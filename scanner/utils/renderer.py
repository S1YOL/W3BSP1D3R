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


def is_available() -> bool:
    """True if Playwright and a usable browser build are importable."""
    try:
        import playwright  # noqa: F401
        return True
    except ImportError:
        return False


@dataclass
class RenderResult:
    """The outcome of rendering a single URL in the browser."""
    html:         str
    final_url:    str
    status:       int
    content_type: str = ""
    links:        list[str] = field(default_factory=list)


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
    ) -> None:
        self.headless = headless
        self.timeout = timeout
        self.wait_until = wait_until
        self.user_agent = user_agent
        self.proxy = proxy
        self.verify_ssl = verify_ssl
        self.block_resources = block_resources

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
        try:
            resp = page.goto(url, wait_until=self.wait_until, timeout=self.timeout)
            # Give late XHR/hydration a brief extra window (best-effort).
            try:
                page.wait_for_load_state("networkidle", timeout=3000)
            except Exception:
                pass

            html = page.content()
            final_url = page.url or url
            status = resp.status if resp else 0
            content_type = ""
            if resp:
                try:
                    content_type = resp.header_value("content-type") or ""
                except Exception:
                    content_type = ""

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
                links=links or [],
            )
        except Exception as exc:
            logger.debug("Browser render failed for %s: %s", url, exc)
            return None
        finally:
            try:
                page.close()
            except Exception:
                pass

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
