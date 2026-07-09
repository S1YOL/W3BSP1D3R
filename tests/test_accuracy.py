from __future__ import annotations
"""
tests/test_accuracy.py
-----------------------
Accuracy harness: runs the real scanner pipeline against a known-vulnerable
app (tests/vulnerable_app.py) and asserts both:

  * RECALL    — every planted vulnerability is detected (true positives)
  * PRECISION — safe endpoints produce no findings (no false positives)

This is the regression safety net that keeps the scanner trustworthy: if a
future change breaks a detector or reintroduces a false positive, these tests
fail. Detectors that need a browser (DOM XSS) are skipped when Playwright is
absent so the core suite stays dependency-light.
"""

import unittest
from urllib.parse import urlparse

from scanner.utils import http as http_utils
from scanner.crawler import Crawler, ApiEndpoint
from scanner.testers.base import set_scope_patterns
from scanner.testers.sqli import SQLiTester
from scanner.testers.xss import XSSTester
from scanner.testers.open_redirect import OpenRedirectTester
from scanner.testers.headers import HeadersTester
from tests.vulnerable_app import VulnerableApp


_app: VulnerableApp | None = None
_pages = None
_api_endpoints: list = []


def setUpModule() -> None:
    global _app, _pages, _api_endpoints
    _app = VulnerableApp().__enter__()
    # Wait for the server to accept connections.
    import time
    import urllib.request
    for _ in range(40):
        try:
            urllib.request.urlopen(_app.url, timeout=1).read()
            break
        except Exception:
            time.sleep(0.1)

    http_utils.init_session(delay=0)
    origin = _app.url
    http_utils.set_allowed_origins({origin})
    set_scope_patterns(include=[], exclude=[])

    crawler = Crawler(base_url=origin, honour_robots=False, max_pages=50)
    _pages = crawler.crawl()
    _api_endpoints = crawler.api_endpoints


def tearDownModule() -> None:
    if _app is not None:
        _app.__exit__(None, None, None)


def _urls(findings) -> str:
    return " ".join(f"{f.vuln_type}@{f.url}" for f in findings)


class TestCrawlDiscovery(unittest.TestCase):
    def test_endpoints_and_params_discovered(self):
        urls = {p.url.split("?")[0] for p in _pages}
        # Homepage links should have been discovered.
        for expected in ("/sqli", "/xss", "/xss_safe", "/redirect", "/redirect_safe"):
            self.assertTrue(
                any(u.endswith(expected) for u in urls),
                f"crawler did not discover {expected} (found: {sorted(urls)})",
            )
        params = {name for p in _pages for name in p.get_params}
        self.assertIn("id", params)
        self.assertIn("q", params)
        self.assertIn("next", params)


class TestRecall(unittest.TestCase):
    """Every planted vulnerability must be detected."""

    def test_sqli_detected(self):
        findings = SQLiTester().run(_pages)
        sqli_urls = [f.url for f in findings]
        self.assertTrue(
            any("/sqli" in u for u in sqli_urls),
            f"error/boolean SQLi not detected (findings: {_urls(findings)})",
        )

    def test_reflected_xss_detected(self):
        findings = XSSTester().run(_pages)
        self.assertTrue(
            any("/xss" in f.url and "xss_safe" not in f.url for f in findings),
            f"reflected XSS not detected (findings: {_urls(findings)})",
        )

    def test_open_redirect_detected(self):
        findings = OpenRedirectTester().run(_pages)
        self.assertTrue(
            any("/redirect" in f.url and "redirect_safe" not in f.url for f in findings),
            f"open redirect not detected (findings: {_urls(findings)})",
        )

    def test_missing_security_headers_detected(self):
        findings = HeadersTester().run(_pages)
        self.assertTrue(
            len(findings) > 0,
            "missing security headers not detected on a header-less app",
        )


class TestPrecision(unittest.TestCase):
    """Safe endpoints must NOT be flagged (no false positives)."""

    def test_encoded_reflection_not_flagged_as_xss(self):
        findings = XSSTester().run(_pages)
        offenders = [f.url for f in findings if "xss_safe" in f.url]
        self.assertEqual(offenders, [], f"false-positive XSS on encoded endpoint: {offenders}")

    def test_safe_redirect_not_flagged(self):
        findings = OpenRedirectTester().run(_pages)
        offenders = [f.url for f in findings if "redirect_safe" in f.url]
        self.assertEqual(offenders, [], f"false-positive open redirect: {offenders}")

    def test_no_sqli_on_non_sql_endpoints(self):
        findings = SQLiTester().run(_pages)
        offenders = [f.url for f in findings if "/xss" in f.url or "/static" in f.url]
        self.assertEqual(offenders, [], f"false-positive SQLi on non-SQL endpoint: {offenders}")


class TestApiDiscovery(unittest.TestCase):
    """Phase D — REST/JSON endpoints must be captured as an injectable surface."""

    def test_json_get_endpoint_recorded_from_crawl(self):
        # /api/search returns application/json, so it is NOT a crawlable HTML page
        # yet must still be recorded as an API endpoint with its query param.
        paths = {urlparse(e.url).path for e in _api_endpoints}
        self.assertIn(
            "/api/search", paths,
            f"JSON API endpoint not captured (endpoints: {sorted(paths)})",
        )
        search = next(e for e in _api_endpoints if urlparse(e.url).path == "/api/search")
        self.assertIn("q", search.query_params)


class TestApiRecall(unittest.TestCase):
    """Phase D — planted API injections must be detected."""

    @staticmethod
    def _run(endpoints):
        tester = SQLiTester()
        tester.set_api_endpoints(endpoints)
        return tester.run([])   # no HTML pages — API surface only

    def test_get_json_query_param_sqli(self):
        eps = [e for e in _api_endpoints if urlparse(e.url).path == "/api/search"]
        self.assertTrue(eps, "no /api/search endpoint discovered to test")
        findings = self._run(eps)
        self.assertTrue(
            any("/api/search" in f.url for f in findings),
            f"error-based SQLi in JSON GET param not detected ({_urls(findings)})",
        )

    def test_json_body_error_based_sqli(self):
        ep = ApiEndpoint(
            url=f"{_app.url}/api/login", method="POST",
            json_body={"username": "admin", "password": "pass"},
        )
        findings = self._run([ep])
        self.assertTrue(
            any(f.parameter == "username" and "/api/login" in f.url for f in findings),
            f"error-based SQLi in JSON body not detected ({_urls(findings)})",
        )

    def test_json_body_boolean_based_sqli(self):
        ep = ApiEndpoint(
            url=f"{_app.url}/api/report", method="POST",
            json_body={"category": "news"},
        )
        findings = self._run([ep])
        self.assertTrue(
            any("/api/report" in f.url for f in findings),
            f"boolean-based blind SQLi in JSON body not detected ({_urls(findings)})",
        )


class TestApiPrecision(unittest.TestCase):
    """Phase D — a JSON endpoint that merely reflects input is NOT injection."""

    def test_reflecting_json_body_not_flagged(self):
        ep = ApiEndpoint(
            url=f"{_app.url}/api/echo", method="POST",
            json_body={"msg": "hello"},
        )
        tester = SQLiTester()
        tester.set_api_endpoints([ep])
        findings = tester.run([])
        self.assertEqual(
            [f.url for f in findings], [],
            f"false-positive SQLi on a reflecting JSON endpoint ({_urls(findings)})",
        )


class TestInteractionDiscovery(unittest.TestCase):
    """Phase E — driving the SPA reveals endpoints that only fire on interaction.

    /spa's search endpoint is called ONLY when the user presses Enter in the
    search box, never on load. So a plain render must NOT discover it, and
    interaction-driven crawling MUST. Skipped when Playwright is unavailable.
    """

    def _api_paths(self, *, interact: bool) -> set[str]:
        from scanner.crawler import Crawler
        crawler = Crawler(
            base_url=f"{_app.url}/spa", honour_robots=False,
            max_pages=2, interact=interact, render=not interact,
        )
        crawler.crawl()
        return {urlparse(e.url).path for e in crawler.api_endpoints}

    def test_interaction_reveals_endpoint_plain_render_misses(self):
        from scanner.utils import renderer as rmod
        if not rmod.is_available():
            self.skipTest("Playwright not installed — interaction test skipped")

        # Plain render (no interaction): the fetch never fires → not discovered.
        self.assertNotIn(
            "/api/search", self._api_paths(interact=False),
            "plain render unexpectedly captured an interaction-only endpoint",
        )
        # Interaction-driven: the search submit fires the fetch → discovered.
        self.assertIn(
            "/api/search", self._api_paths(interact=True),
            "interaction-driven crawling did not reveal the search endpoint",
        )


class TestDomXss(unittest.TestCase):
    def test_dom_xss_detected_when_browser_available(self):
        from scanner.utils import renderer as rmod
        if not rmod.is_available():
            self.skipTest("Playwright not installed — DOM XSS test skipped")

        from scanner.testers.dom_xss import DOMXSSTester
        from scanner.crawler import CrawledPage

        page = CrawledPage(url=f"{_app.url}/dom", status=200, forms=[], get_params={})
        findings = DOMXSSTester().run([page])
        self.assertTrue(
            any("DOM" in f.vuln_type for f in findings),
            f"DOM XSS via location.hash not detected (findings: {_urls(findings)})",
        )


if __name__ == "__main__":
    unittest.main()
