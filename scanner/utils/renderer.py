from __future__ import annotations
"""
scanner/utils/renderer.py
--------------------------
Headless-browser rendering layer (Playwright/Chromium).

Why this exists:
  The default crawler only sees server-rendered HTML. Modern applications
  (React, Vue, Angular, Next.js, Svelte, …) build their DOM in the browser
  with JavaScript, so a plain HTTP GET returns an almost-empty shell. This
  module renders each page in a real headless browser, waits for the SPA to
  hydrate, and returns the *rendered* DOM — dramatically improving link and
  form discovery on JavaScript-heavy targets.

It is an OPTIONAL dependency. If Playwright (and its Chromium build) are not
installed, is_available() returns False and the scanner transparently falls
back to the static HTTP crawler.

    pip install playwright
    playwright install chromium
"""

import logging
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


# Substrings (case-insensitive) that mark a control as potentially destructive or
# session-ending. Interaction-driven crawling NEVER clicks these — a scanner must
# not delete data, log itself out, or place orders while mapping the app.
_DESTRUCTIVE_TEXT = (
    "delete", "remove", "destroy", "drop", "wipe", "erase", "trash",
    "logout", "log out", "sign out", "signout",
    "buy", "checkout", "purchase", "pay", "order now", "place order",
    "cancel", "unsubscribe", "deactivate", "close account", "reset",
    "confirm", "submit order", "withdraw", "transfer",
)

# Benign values used to fill inputs so forms submit cleanly (and fire their XHR)
# without injecting anything — injection happens later, against the endpoints
# these interactions reveal.
_BENIGN_FILL = {
    "email":    "test@example.com",
    "password": "Passw0rd!23",
    "search":   "test",
    "url":      "http://example.com",
    "tel":      "5551234567",
    "number":   "1",
    "date":     "2020-01-01",
    "text":     "test",
}


def is_available() -> bool:
    """True if Playwright and a usable browser build are importable."""
    try:
        import playwright  # noqa: F401
        return True
    except ImportError:
        return False


@dataclass
class ApiRequest:
    """An XHR/fetch call the page made while rendering — a REST/JSON API endpoint
    that the SPA talks to. These are the injectable surfaces a static crawler
    never sees."""
    url:          str
    method:       str
    resource_type: str = ""       # "xhr" or "fetch"
    post_data:    str | None = None
    content_type: str = ""         # request Content-Type (e.g. application/json)


@dataclass
class RenderResult:
    """The outcome of rendering a single URL in the browser."""
    html:         str
    final_url:    str
    status:       int
    content_type: str = ""
    links:        list[str] = field(default_factory=list)
    api_requests: list[ApiRequest] = field(default_factory=list)


class BrowserRenderer:
    """
    Context-managed headless Chromium wrapper.

    Usage:
        with BrowserRenderer(timeout=15000) as r:
            result = r.render("https://example.com")

    IMPORTANT: Playwright's sync API is bound to the thread that starts it.
    Create and use a BrowserRenderer entirely within a single thread (the
    crawler uses one on the main thread; the DOM-XSS tester uses one inside its
    own worker-thread run()). Do not share an instance across threads.
    """

    def __init__(
        self,
        headless: bool = True,
        timeout: int = 15000,
        wait_until: str = "networkidle",
        user_agent: str | None = None,
        proxy: str | None = None,
        verify_ssl: bool = True,
        block_resources: bool = True,
        interact: bool = False,
    ) -> None:
        self.headless = headless
        self.timeout = timeout
        self.wait_until = wait_until
        self.user_agent = user_agent
        self.proxy = proxy
        self.verify_ssl = verify_ssl
        self.block_resources = block_resources
        # Phase E: drive safe SPA interactions (search, form submit, safe clicks)
        # so injectable XHR/fetch endpoints fire and get captured.
        self.interact = interact

        self._pw = None
        self._browser = None
        self._context = None

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def __enter__(self) -> "BrowserRenderer":
        from playwright.sync_api import sync_playwright

        self._pw = sync_playwright().start()
        self._browser = self._pw.chromium.launch(headless=self.headless)
        self._context = self._browser.new_context(
            user_agent=self.user_agent,
            ignore_https_errors=not self.verify_ssl,
            proxy={"server": self.proxy} if self.proxy else None,
        )
        self._context.set_default_timeout(self.timeout)
        if self.block_resources:
            # Speed: skip images/media/fonts — we only care about DOM + scripts.
            self._context.route("**/*", self._route_filter)
        return self

    def __exit__(self, *exc) -> None:
        for closer in (self._context, self._browser):
            try:
                if closer:
                    closer.close()
            except Exception:
                pass
        try:
            if self._pw:
                self._pw.stop()
        except Exception:
            pass

    @staticmethod
    def _route_filter(route) -> None:
        try:
            if route.request.resource_type in ("image", "media", "font"):
                route.abort()
            else:
                route.continue_()
        except Exception:
            try:
                route.continue_()
            except Exception:
                pass

    # ------------------------------------------------------------------
    # Rendering
    # ------------------------------------------------------------------

    def render(self, url: str) -> RenderResult | None:
        """Render a URL and return the rendered DOM + discovered links.
        Returns None on navigation failure."""
        if not self._context:
            raise RuntimeError("BrowserRenderer used outside its context manager")

        page = self._context.new_page()

        # Capture XHR/fetch calls the SPA makes — these are the REST/JSON API
        # endpoints (the injectable surface a static crawler can't see).
        api_requests: list[ApiRequest] = []

        def _on_request(request) -> None:
            try:
                if request.resource_type not in ("xhr", "fetch"):
                    return
                headers = {}
                try:
                    headers = request.headers or {}
                except Exception:
                    headers = {}
                api_requests.append(ApiRequest(
                    url=request.url,
                    method=(request.method or "GET").upper(),
                    resource_type=request.resource_type,
                    post_data=request.post_data,
                    content_type=headers.get("content-type", ""),
                ))
            except Exception:
                pass

        page.on("request", _on_request)

        try:
            resp = page.goto(url, wait_until=self.wait_until, timeout=self.timeout)
            # Give late XHR/hydration a brief extra window (best-effort).
            try:
                page.wait_for_load_state("networkidle", timeout=3000)
            except Exception:
                pass

            # The page's identity is where the initial navigation landed — capture
            # it BEFORE interactions, which will wander off to other routes.
            final_url = page.url or url
            status = resp.status if resp else 0
            content_type = ""
            if resp:
                try:
                    content_type = resp.header_value("content-type") or ""
                except Exception:
                    content_type = ""
            html = page.content()

            # Phase E: drive safe interactions so injectable XHR endpoints fire.
            # The request handler above stays attached, so anything these actions
            # trigger is captured into `api_requests` automatically. Routes the
            # interactions navigate to are returned as links so the crawler renders
            # each one FRESH (a client-side nav often doesn't re-fire the route's
            # data XHR, but a direct load of it does).
            interaction_routes: list[str] = []
            if self.interact:
                interaction_routes = self._drive_interactions(page) or []
                # Prefer the post-interaction DOM for link discovery (more anchors
                # are present after menus/routes have opened).
                html = page.content()

            # Anchors resolved to absolute URLs by the DOM (includes JS-added ones).
            try:
                links = page.eval_on_selector_all(
                    "a[href]", "els => els.map(e => e.href)"
                )
            except Exception:
                links = []

            return RenderResult(
                html=html,
                final_url=final_url,
                status=status,
                content_type=content_type,
                links=(links or []) + interaction_routes,
                api_requests=api_requests,
            )
        except Exception as exc:
            logger.debug("Browser render failed for %s: %s", url, exc)
            return None
        finally:
            try:
                page.close()
            except Exception:
                pass

    # ------------------------------------------------------------------
    # Phase E — interaction-driven crawling
    # ------------------------------------------------------------------

    def _drive_interactions(self, page) -> list[str]:
        """Perform a bounded, non-destructive set of interactions so the SPA
        fires its data-loading XHR/fetch calls (search, form submit, in-app
        navigation). Every step is best-effort and independently guarded so one
        stale element or slow control can't abort the crawl.

        Returns every distinct in-app route URL the interactions landed on, so the
        crawler can render each one FRESH (a later step may navigate away before a
        route's debounced data XHR is captured — a direct load of it won't)."""
        routes: list[str] = []

        def _mark() -> None:
            try:
                u = page.url
                if u and u not in routes:
                    routes.append(u)
            except Exception:
                pass

        self._settle(page, 1200)
        for step in (self._interact_search, self._interact_forms, self._interact_clicks):
            try:
                step(page)
            except Exception as exc:
                logger.debug("interaction step %s failed: %s", step.__name__, exc)
            _mark()   # record the route this step left us on, before the next moves on
        # A route change kicked off by an interaction often loads its data via a
        # debounced XHR that lands after the step returns — wait once more so those
        # late endpoints are captured too.
        self._settle(page, 2500)
        _mark()
        return routes

    @staticmethod
    def _settle(page, ms: int = 1200) -> None:
        try:
            page.wait_for_load_state("networkidle", timeout=ms)
        except Exception:
            pass

    def _safe_text(self, el) -> bool:
        """True unless the element's visible text / aria-label / value looks
        destructive or session-ending (see _DESTRUCTIVE_TEXT)."""
        parts = []
        try:
            parts.append(el.inner_text() or "")
        except Exception:
            pass
        for attr in ("aria-label", "value", "title"):
            try:
                parts.append(el.get_attribute(attr) or "")
            except Exception:
                pass
        low = " ".join(parts).lower()
        return not any(bad in low for bad in _DESTRUCTIVE_TEXT)

    def _interact_search(self, page) -> None:
        """Reveal a search box (some are behind a toggle) then submit a benign
        query — this is what fires endpoints like /rest/products/search?q=…"""
        for sel in ('[aria-label*="search" i]', 'button[class*="search" i]',
                    '[class*="search" i] button'):
            try:
                el = page.query_selector(sel)
                if el and el.is_visible() and self._safe_text(el):
                    el.click(timeout=1500)
                    self._settle(page, 800)
                    break
            except Exception:
                continue

        for sel in ('input[type="search"]', 'input[placeholder*="search" i]',
                    'input[aria-label*="search" i]', 'input[name*="search" i]',
                    'input#searchQuery', 'input[type="text"]'):
            try:
                for el in page.query_selector_all(sel):
                    if el.is_visible():
                        el.fill(_BENIGN_FILL["search"], timeout=1200)
                        el.press("Enter")
                        self._settle(page, 1500)
                        return
            except Exception:
                continue

    def _interact_forms(self, page, max_forms: int = 3) -> None:
        """Fill visible forms with benign values and submit them so their XHR
        (login, register, feedback, …) fires and gets captured."""
        try:
            forms = page.query_selector_all("form")
        except Exception:
            return
        for form in forms[:max_forms]:
            try:
                if not form.is_visible():
                    continue
                self._fill_inputs(form)
                btn = None
                try:
                    btn = form.query_selector(
                        'button[type="submit"], input[type="submit"], button:not([type])'
                    )
                except Exception:
                    btn = None
                if btn and btn.is_visible() and self._safe_text(btn):
                    btn.click(timeout=1500)
                else:
                    form.evaluate(
                        "f => { if (f.requestSubmit) f.requestSubmit(); "
                        "else if (f.submit) f.submit(); }"
                    )
                self._settle(page, 1200)
            except Exception:
                continue

    def _fill_inputs(self, scope) -> None:
        """Fill visible text-like inputs within `scope` using benign values."""
        try:
            inputs = scope.query_selector_all("input, textarea")
        except Exception:
            return
        for inp in inputs:
            try:
                if not inp.is_visible():
                    continue
                itype = (inp.get_attribute("type") or "text").lower()
                if itype in ("hidden", "submit", "button", "checkbox",
                             "radio", "file", "image", "reset"):
                    continue
                inp.fill(_BENIGN_FILL.get(itype, _BENIGN_FILL["text"]), timeout=1000)
            except Exception:
                continue

    def _interact_clicks(self, page, budget: int = 6) -> None:
        """Click a bounded number of non-destructive navigational controls to
        trigger in-app route changes / lazy data loads."""
        clicked = 0
        for sel in ('[routerlink]', 'button', '[role="button"]', 'a[href^="#"]'):
            if clicked >= budget:
                break
            try:
                els = page.query_selector_all(sel)
            except Exception:
                continue
            for el in els:
                if clicked >= budget:
                    break
                try:
                    if not el.is_visible() or not self._safe_text(el):
                        continue
                    el.click(timeout=1200)
                    clicked += 1
                    self._settle(page, 700)
                except Exception:
                    continue

    def new_page_with_dialog_capture(self, sink: list):
        """Create a page whose alert/confirm/prompt dialogs are captured into
        `sink` (list of message strings) and auto-dismissed. Used by the
        DOM-XSS tester to prove client-side script execution."""
        if not self._context:
            raise RuntimeError("BrowserRenderer used outside its context manager")
        page = self._context.new_page()

        def _on_dialog(dialog):
            try:
                sink.append(dialog.message)
            finally:
                try:
                    dialog.dismiss()
                except Exception:
                    pass

        page.on("dialog", _on_dialog)
        return page
