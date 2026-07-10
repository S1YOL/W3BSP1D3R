from __future__ import annotations
"""
scanner/crawler.py
-------------------
Web crawler — discovers URLs, forms, and GET parameters within the target
application's scope.

Security concept:
  Before any vulnerability testing can happen, a scanner must map the attack
  surface. This crawler performs a breadth-first traversal of the target site,
  collecting:
    - All reachable internal URLs (same origin only — we never leave scope)
    - Every HTML <form> including its action, method, and input fields
    - GET parameters extracted from discovered URLs

  Staying in-scope is both a technical necessity and an ethical obligation:
  a well-written scanner MUST NOT follow links to third-party domains.

Limitations (intentional — this is an educational tool):
  - JavaScript-rendered content is NOT crawled (would require Selenium/Playwright)
  - Only href and action attributes are followed; JS event handlers are ignored
  - robots.txt is respected by default (honourRobots=True)
"""

import json as _json
import logging
from collections import deque
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse, urlunparse, parse_qs
try:
    from defusedxml.ElementTree import fromstring as _safe_xml_fromstring
except ImportError:
    # Fallback: strip DOCTYPE to block entity expansion
    import re as _re
    import xml.etree.ElementTree as _ET

    def _safe_xml_fromstring(text: str):  # type: ignore[misc]
        sanitized = _re.sub(r"<!DOCTYPE[^>]*>", "", text, count=1)
        return _ET.fromstring(sanitized)

from bs4 import BeautifulSoup

from scanner.utils import http as http_utils
from scanner.utils.display import print_status, print_warning

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data structures produced by the crawler
# ---------------------------------------------------------------------------

@dataclass
class FormField:
    """Represents a single input element inside an HTML form."""
    name:     str
    field_type: str   # text, hidden, password, textarea, select, etc.
    value:    str = ""


@dataclass
class CrawledForm:
    """A complete HTML form discovered during crawling."""
    page_url:   str               # page the form lives on
    action_url: str               # where the form POSTs/GETs to
    method:     str               # "GET" or "POST"
    fields:     list[FormField] = field(default_factory=list)

    @property
    def testable_fields(self) -> list[FormField]:
        """
        Fields that accept user input — these are injection targets.
        Excludes submit buttons and hidden fields (tested separately for CSRF).
        """
        injectable = {"text", "email", "search", "url", "number", "tel",
                      "textarea", "password", "date", "time"}
        return [f for f in self.fields if f.field_type in injectable]

    @property
    def hidden_fields(self) -> list[FormField]:
        """Hidden fields only — used by the CSRF tester."""
        return [f for f in self.fields if f.field_type == "hidden"]


@dataclass
class CrawledPage:
    """Everything discovered on a single crawled page."""
    url:        str
    status:     int
    forms:      list[CrawledForm] = field(default_factory=list)
    get_params: dict[str, list[str]] = field(default_factory=dict)  # param → [values]


@dataclass
class ApiEndpoint:
    """A REST/JSON API endpoint discovered from SPA XHR/fetch traffic (or a JSON
    URL supplied directly). Unlike an HTML page, its injectable surface lives in
    query-string parameters and/or JSON request-body fields — the two things the
    Phase D injection pass fuzzes.

    Security concept:
      Modern applications are API-first: the browser renders a shell, then talks
      to `/rest/...` or `/api/...` endpoints over JSON. A classic HTML crawler
      never records these (the responses aren't HTML), so their parameters go
      untested. Capturing them is what lets the scanner reach injection points on
      SPA / API-first targets.
    """
    url:          str                              # full URL incl. query string
    method:       str                              # GET / POST / PUT / PATCH / DELETE
    query_params: dict[str, list[str]] = field(default_factory=dict)
    json_body:    dict | None = None               # parsed JSON body (if any)
    content_type: str = ""

    @property
    def signature(self) -> tuple:
        """Stable identity for de-duplication: method + path + which parameters
        are present (not their values), so we test each shape once."""
        path = urlparse(self.url).path
        body_keys = tuple(sorted(self.json_body.keys())) if isinstance(self.json_body, dict) else ()
        return (self.method, path, tuple(sorted(self.query_params.keys())), body_keys)


# ---------------------------------------------------------------------------
# Crawler
# ---------------------------------------------------------------------------

class Crawler:
    """
    Breadth-first web crawler scoped to a single origin.

    Usage:
        crawler = Crawler(base_url="http://localhost:80/dvwa")
        pages   = crawler.crawl(max_pages=50)
    """

    # Suffixes we'll never bother fetching (static assets, binary files)
    _SKIP_EXTENSIONS = {
        ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp",
        ".css", ".js", ".woff", ".woff2", ".ttf", ".eot",
        ".pdf", ".zip", ".tar", ".gz", ".mp4", ".mp3",
    }

    def __init__(
        self,
        base_url: str,
        honour_robots: bool = True,
        max_pages: int = 100,
        render: bool = False,
        interact: bool = False,
    ) -> None:
        """
        Args:
            base_url       : Root URL — only pages under this origin are crawled.
            honour_robots  : If True, fetch and respect robots.txt disallow rules.
            max_pages      : Hard cap on pages to visit (prevents runaway scans).
            render         : If True, render each page in a headless browser so
                             JavaScript/SPA content is discovered. Falls back to
                             the static HTTP crawler if Playwright is unavailable.
        """
        parsed         = urlparse(base_url)
        # Canonical origin: scheme + netloc (e.g. "http://localhost:80")
        self.origin    = f"{parsed.scheme}://{parsed.netloc}"
        self.base_url  = base_url.rstrip("/")
        self.max_pages = max_pages
        # Interaction-driven crawling (Phase E) only makes sense with a browser,
        # so requesting it implies rendering.
        self.interact  = interact
        self.render    = render or interact

        self._visited:      set[str]          = set()
        self._queue:        deque[str]        = deque([base_url])
        self._disallowed:   set[str]          = set()
        self.pages:         list[CrawledPage] = []
        self.api_endpoints: list[ApiEndpoint] = []   # REST/JSON endpoints (Phase D)
        self._api_seen:     set[tuple]        = set()
        self._renderer                        = None  # set during crawl() if render

        if honour_robots:
            self._load_robots_txt()
        self._load_sitemap()

    # ------------------------------------------------------------------
    # Main crawl entry point
    # ------------------------------------------------------------------

    def crawl(self) -> list[CrawledPage]:
        """
        Execute the crawl and return all discovered CrawledPage objects.

        The crawl stops when:
          - The queue is empty (all reachable pages visited), OR
          - max_pages has been reached.

        If render=True and Playwright is available, pages are rendered in a
        headless browser so JavaScript-built DOM is crawled.
        """
        if self.render:
            self._enter_renderer()
        try:
            self._crawl_loop()
        finally:
            self._exit_renderer()

        logger.info(
            "Crawl finished: %d pages visited, %d forms found",
            len(self._visited),
            sum(len(p.forms) for p in self.pages),
        )
        return self.pages

    def _crawl_loop(self) -> None:
        while self._queue and len(self._visited) < self.max_pages:
            url = self._queue.popleft()

            # Normalise and deduplicate
            url = self._normalise(url)
            if url in self._visited:
                continue
            if not self._in_scope(url):
                continue
            if self._is_disallowed(url):
                logger.debug("robots.txt disallows %s — skipping", url)
                continue
            if self._has_skip_extension(url):
                continue

            self._visited.add(url)
            page = self._fetch_and_parse(url)
            if page:
                self.pages.append(page)

    def _enter_renderer(self) -> None:
        """Start the headless browser for the crawl, or fall back to HTTP."""
        from scanner.utils import renderer as _renderer_mod
        if not _renderer_mod.is_available():
            print_warning(
                "Browser rendering requested but Playwright is not installed — "
                "falling back to static crawling. Install with: "
                "pip install playwright && playwright install chromium"
            )
            self.render = False
            return
        try:
            self._renderer = _renderer_mod.BrowserRenderer(interact=self.interact)
            self._renderer.__enter__()
            mode = "JavaScript rendering + interaction" if self.interact else "JavaScript rendering"
            print_status(f"Headless browser started ({mode} enabled)")
        except Exception as exc:
            print_warning(f"Failed to start headless browser: {exc} — using static crawl")
            self._renderer = None
            self.render = False

    def _exit_renderer(self) -> None:
        if self._renderer:
            try:
                self._renderer.__exit__(None, None, None)
            except Exception:
                pass
            self._renderer = None

    # ------------------------------------------------------------------
    # Fetch + parse a single page
    # ------------------------------------------------------------------

    def _fetch_and_parse(self, url: str) -> CrawledPage | None:
        """
        GET a URL, parse its HTML, extract links and forms.

        Handles redirects gracefully — if the server redirects to a
        different path on the same origin, we use the final URL for
        link resolution and also add the redirected URL to visited set.

        Returns a CrawledPage or None on error.
        """
        # --- Render path (headless browser) ---------------------------------
        if self._renderer:
            rr = self._renderer.render(url)
            if not rr:
                return None
            final_url = rr.final_url or url
            if not self._same_origin_ok(url, final_url):
                return None
            # Rendered documents are HTML; content_type is often present but may
            # be blank for SPA navigations, so only reject on an explicit non-HTML type.
            if rr.content_type and "html" not in rr.content_type.lower():
                logger.debug("Skipping non-HTML (%s) at %s", rr.content_type, final_url)
                return None
            status_code, html = rr.status, rr.html
            print_status(f"[{status_code}] {final_url} (rendered)")
            soup = BeautifulSoup(html, "lxml")
            # Enqueue browser-resolved anchors (JS-added links included). Keep SPA
            # hash-routes (#/…) intact so each is crawled as its own page; strip
            # only plain in-page anchors (#section).
            for link in rr.links:
                clean = link if self._is_spa_route(link) else link.split("#")[0]
                if self._in_scope(clean) and self._normalise(clean) not in self._visited:
                    self._queue.append(clean)
            # Record REST/JSON API endpoints the SPA called (Phase D).
            for req in rr.api_requests:
                self._record_api_endpoint(
                    url=req.url,
                    method=req.method,
                    post_data=req.post_data,
                    content_type=req.content_type,
                )
        else:
            # --- Static HTTP path -------------------------------------------
            try:
                resp = http_utils.get(url)
            except Exception as exc:
                print_warning(f"Fetch failed for {url}: {exc}")
                return None

            final_url = resp.url if resp.url else url
            if final_url != url and not self._same_origin_ok(url, final_url):
                return None

            content_type = resp.headers.get("Content-Type", "")
            if "text/html" not in content_type:
                # A JSON endpoint supplied directly (e.g. --url .../search?q=x) is
                # not an HTML page, but if it carries query parameters it's still a
                # testable injection surface — record it for the Phase D API pass.
                if "json" in content_type.lower():
                    self._record_api_endpoint(
                        url=final_url, method="GET", content_type=content_type,
                    )
                logger.debug("Skipping non-HTML content at %s (%s)", final_url, content_type)
                return None

            print_status(f"[{resp.status_code}] {final_url}")
            status_code = resp.status_code
            soup = BeautifulSoup(resp.text, "lxml")

        # Enqueue newly discovered <a href> links (resolve against final URL)
        for link in self._extract_links(soup, final_url):
            if link not in self._visited:
                self._queue.append(link)

        # Parse forms
        forms      = self._extract_forms(soup, final_url)
        get_params = self._extract_get_params(final_url)

        return CrawledPage(
            url=final_url,
            status=status_code,
            forms=forms,
            get_params=get_params,
        )

    def _same_origin_ok(self, url: str, final_url: str) -> bool:
        """Handle a redirect: accept same-origin (recording it as visited),
        reject cross-origin."""
        if final_url == url:
            return True
        final_parsed = urlparse(final_url)
        final_origin = f"{final_parsed.scheme}://{final_parsed.netloc}"
        if final_origin == self.origin:
            self._visited.add(self._normalise(final_url))
            logger.debug("Followed redirect: %s → %s", url, final_url)
            return True
        print_warning(f"Redirect to different origin: {url} → {final_url}")
        return False

    # ------------------------------------------------------------------
    # Link extraction
    # ------------------------------------------------------------------

    def _extract_links(self, soup: BeautifulSoup, base: str) -> list[str]:
        """
        Collect all <a href> links on a page, resolved to absolute URLs.
        Stays in-scope and skips fragment-only anchors.
        """
        links = []
        for tag in soup.find_all("a", href=True):
            href = tag["href"].strip()

            # Skip empty, javascript:, mailto:, tel: links.
            if not href or href.startswith(("javascript:", "mailto:", "tel:")):
                continue

            absolute = urljoin(base, href)
            # Keep SPA hash-routes (#/…) intact; strip plain in-page anchors.
            if self._is_spa_route(absolute):
                pass
            elif href.startswith("#"):
                continue  # in-page anchor only — nothing new to crawl
            else:
                absolute = absolute.split("#")[0]

            if self._in_scope(absolute):
                links.append(absolute)

        return links

    # ------------------------------------------------------------------
    # Form extraction
    # ------------------------------------------------------------------

    def _extract_forms(self, soup: BeautifulSoup, page_url: str) -> list[CrawledForm]:
        """
        Parse all <form> elements on a page.

        For each form we collect:
          - The resolved action URL (defaults to page_url if missing)
          - The method (defaults to GET)
          - All input, textarea, and select elements with their names/values
        """
        forms = []
        for form_tag in soup.find_all("form"):
            raw_action = form_tag.get("action", "")
            action_url = urljoin(page_url, raw_action) if raw_action else page_url
            method     = (form_tag.get("method", "get") or "get").upper().strip()

            fields: list[FormField] = []

            # Collect <input> elements
            for inp in form_tag.find_all("input"):
                name  = inp.get("name", "").strip()
                itype = inp.get("type", "text").lower().strip()
                value = inp.get("value", "")
                if name:
                    fields.append(FormField(name=name, field_type=itype, value=value))

            # Collect <textarea> elements
            for ta in form_tag.find_all("textarea"):
                name = ta.get("name", "").strip()
                if name:
                    fields.append(FormField(name=name, field_type="textarea", value=ta.get_text(strip=True)))

            # Collect <select> elements (grab first option value as default)
            for sel in form_tag.find_all("select"):
                name = sel.get("name", "").strip()
                if name:
                    first_option = sel.find("option")
                    value = first_option.get("value", "") if first_option else ""
                    fields.append(FormField(name=name, field_type="select", value=value))

            if fields:
                forms.append(CrawledForm(
                    page_url=page_url,
                    action_url=action_url,
                    method=method,
                    fields=fields,
                ))

        return forms

    # ------------------------------------------------------------------
    # GET parameter extraction
    # ------------------------------------------------------------------

    def _extract_get_params(self, url: str) -> dict[str, list[str]]:
        """
        Extract GET query parameters from a URL.

        Example:
            /search?q=hello&page=1  →  {"q": ["hello"], "page": ["1"]}

        These parameters are injection targets for SQLi and XSS testers.

        keep_blank_values=True is important: an endpoint like /search?q= (empty
        default, common in SPAs that populate it later) still exposes an injectable
        `q` parameter — dropping it would leave the endpoint untested.
        """
        parsed = urlparse(url)
        return parse_qs(parsed.query, keep_blank_values=True)  # {name: [value, ...]}

    # ------------------------------------------------------------------
    # REST/JSON API endpoint capture (Phase D)
    # ------------------------------------------------------------------

    def _record_api_endpoint(
        self,
        url: str,
        method: str,
        post_data: str | None = None,
        content_type: str = "",
    ) -> None:
        """
        Register a REST/JSON API endpoint for injection testing, if it exposes a
        testable surface (query params and/or a JSON body) and is in-scope.

        De-duplicated by (method, path, param-names, body-keys) so we test each
        distinct endpoint shape exactly once regardless of how many times the SPA
        called it.
        """
        if not self._in_scope(url):
            return

        query_params = self._extract_get_params(url)

        json_body: dict | None = None
        if post_data:
            ct = (content_type or "").lower()
            looks_json = "json" in ct or post_data.lstrip().startswith(("{", "["))
            if looks_json:
                try:
                    parsed = _json.loads(post_data)
                    if isinstance(parsed, dict):
                        json_body = parsed
                except (ValueError, TypeError):
                    json_body = None

        # Nothing to fuzz → don't record (avoids noise from param-less GETs).
        if not query_params and not json_body:
            return

        endpoint = ApiEndpoint(
            url=url,
            method=(method or "GET").upper(),
            query_params=query_params,
            json_body=json_body,
            content_type=content_type,
        )
        sig = endpoint.signature
        if sig in self._api_seen:
            return
        self._api_seen.add(sig)
        self.api_endpoints.append(endpoint)
        logger.debug("Recorded API endpoint: %s %s (params=%s, body_keys=%s)",
                     endpoint.method, url,
                     list(query_params.keys()),
                     list(json_body.keys()) if json_body else [])

    # ------------------------------------------------------------------
    # Robots.txt support
    # ------------------------------------------------------------------

    def _load_robots_txt(self) -> None:
        """
        Fetch and parse robots.txt, storing disallowed paths.
        We respect 'User-agent: *' Disallow directives as a minimum.
        """
        robots_url = f"{self.origin}/robots.txt"
        try:
            resp = http_utils.get(robots_url)
            if resp.status_code == 200:
                self._parse_robots(resp.text)
        except Exception:
            pass  # robots.txt not found — no restrictions

    def _parse_robots(self, text: str) -> None:
        """Extract Disallow paths for '*' user-agent from robots.txt content."""
        active = False
        for line in text.splitlines():
            line = line.strip().lower()
            if line.startswith("user-agent:"):
                agent = line.split(":", 1)[1].strip()
                active = agent == "*"
            elif active and line.startswith("disallow:"):
                path = line.split(":", 1)[1].strip()
                if path:
                    self._disallowed.add(path)

    def _load_sitemap(self) -> None:
        """
        Fetch /sitemap.xml and /sitemap_index.xml, extract <loc> URLs, and
        seed the crawl queue. This significantly expands attack surface
        discovery on well-structured sites.
        """
        candidates = [
            f"{self.origin}/sitemap.xml",
            f"{self.origin}/sitemap_index.xml",
            f"{self.origin}/sitemap",
        ]
        for sitemap_url in candidates:
            try:
                resp = http_utils.get(sitemap_url)
                if resp.status_code != 200:
                    continue
                ct = resp.headers.get("Content-Type", "")
                if "xml" not in ct and "text" not in ct:
                    continue
                added = 0
                try:
                    root = _safe_xml_fromstring(resp.text)
                    locs = [e.text.strip() for e in root.iter()
                            if e.tag in ("loc", "{http://www.sitemaps.org/schemas/sitemap/0.9}loc")
                            and e.text]
                except Exception:
                    locs = []
                for loc in locs:
                    if self._in_scope(loc) and loc not in self._visited:
                        self._queue.append(loc)
                        added += 1
                if added:
                    logger.debug("Sitemap %s: queued %d URLs", sitemap_url, added)
            except Exception:
                pass  # sitemap absent — that's fine

    def _is_disallowed(self, url: str) -> bool:
        path = urlparse(url).path
        return any(path.startswith(d) for d in self._disallowed)

    # ------------------------------------------------------------------
    # Scope / URL helpers
    # ------------------------------------------------------------------

    def _in_scope(self, url: str) -> bool:
        """Return True only if `url` belongs to the same origin as base_url."""
        parsed = urlparse(url)
        candidate_origin = f"{parsed.scheme}://{parsed.netloc}"
        return candidate_origin == self.origin

    @staticmethod
    def _is_spa_route(url: str) -> bool:
        """True for client-side SPA routes carried in the fragment, e.g.
        http://app/#/search?q=x (Angular/Vue/React hash routing). These are
        distinct pages that must be crawled individually — unlike a plain
        in-page anchor (#section), which is not."""
        frag = urlparse(url).fragment
        return frag.startswith(("/", "!/", "!"))

    @staticmethod
    def _normalise(url: str) -> str:
        """
        Normalise a URL for deduplication:
          - Remove trailing slash (except for root)
          - Lower-case the scheme and host
          - Remove default ports (:80 for http, :443 for https)
          - Drop in-page anchors, but PRESERVE SPA hash-routes (#/…), which are
            genuinely different pages.
        """
        p = urlparse(url)
        host = p.hostname or ""
        port = p.port
        if (p.scheme == "http" and port == 80) or (p.scheme == "https" and port == 443):
            netloc = host
        else:
            netloc = f"{host}:{port}" if port else host

        path = p.path.rstrip("/") or "/"
        fragment = p.fragment if Crawler._is_spa_route(url) else ""
        return urlunparse((p.scheme, netloc, path, p.params, p.query, fragment))

    @staticmethod
    def _has_skip_extension(url: str) -> bool:
        path = urlparse(url).path.lower()
        return any(path.endswith(ext) for ext in Crawler._SKIP_EXTENSIONS)

    # ------------------------------------------------------------------
    # Convenience accessors
    # ------------------------------------------------------------------

    @property
    def all_forms(self) -> list[CrawledForm]:
        """Flat list of every form found across all crawled pages."""
        return [form for page in self.pages for form in page.forms]

    @property
    def all_get_param_urls(self) -> list[tuple[str, str]]:
        """
        List of (url, param_name) tuples for every discovered GET parameter.
        Used directly by SQLi and XSS testers.
        """
        result = []
        for page in self.pages:
            for param in page.get_params:
                result.append((page.url, param))
        return result
