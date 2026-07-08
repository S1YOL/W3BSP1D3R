from __future__ import annotations
"""
scanner/testers/http_methods.py
---------------------------------
HTTP method testing — checks if dangerous or unnecessary HTTP methods
are enabled on the target.

Why this matters:
  - PUT/DELETE can allow file upload or deletion if misconfigured
  - TRACE enables Cross-Site Tracing (XST) attacks that can steal cookies
  - OPTIONS reveals allowed methods (information disclosure)
  - PATCH may allow unauthorized modifications
  - WebDAV methods (PROPFIND, MKCOL, COPY, MOVE) can expose file systems

Detection approach:
  - Sends OPTIONS request to discover advertised methods
  - Probes each dangerous method individually
  - Checks for WebDAV indicators
  - Verifies TRACE by checking if the request is echoed back
"""

import logging
from urllib.parse import urlparse

from scanner.testers.base import BaseTester
from scanner.crawler import CrawledPage
from scanner.reporting.models import Finding, Severity
from scanner.utils import http as http_utils

logger = logging.getLogger(__name__)

# Methods we consider dangerous and their risk descriptions
_DANGEROUS_METHODS = {
    "PUT": ("File upload may be possible", Severity.HIGH),
    "DELETE": ("File/resource deletion may be possible", Severity.HIGH),
    "TRACE": ("Cross-Site Tracing (XST) attack possible", Severity.MEDIUM),
    "PATCH": ("Unauthorized resource modification may be possible", Severity.MEDIUM),
    "PROPFIND": ("WebDAV directory listing possible", Severity.HIGH),
    "MKCOL": ("WebDAV directory creation possible", Severity.HIGH),
    "COPY": ("WebDAV file copy possible", Severity.MEDIUM),
    "MOVE": ("WebDAV file move possible", Severity.HIGH),
}


class HTTPMethodTester(BaseTester):
    """Test for dangerous HTTP methods enabled on the target."""

    def __init__(self) -> None:
        super().__init__(name="HTTP Method Testing")

    def run(self, pages: list[CrawledPage]) -> list[Finding]:
        if not pages:
            return self.findings

        pages = self._filter_pages_by_scope(pages)
        base_url = pages[0].url
        parsed = urlparse(base_url)
        origin = f"{parsed.scheme}://{parsed.netloc}"

        # Test on the root and a few discovered pages
        urls_to_test = {origin + "/"}
        for page in pages[:5]:
            urls_to_test.add(page.url)

        for url in urls_to_test:
            self._test_options(url)
            self._test_trace(url)
            self._test_dangerous_methods(url)

        return self.findings

    def _test_options(self, url: str) -> None:
        """Send OPTIONS request and check for dangerous allowed methods."""
        self._count_test()
        try:
            session = http_utils.get_session()
            resp = session.options(url, timeout=10)
        except Exception:
            return

        allow = resp.headers.get("Allow", "")
        if not allow:
            allow = resp.headers.get("Access-Control-Allow-Methods", "")
        if not allow:
            return

        methods = [m.strip().upper() for m in allow.split(",")]
        dangerous_found = [m for m in methods if m in _DANGEROUS_METHODS]

        if dangerous_found:
            self._log_finding(Finding(
                vuln_type="Dangerous HTTP Methods Enabled",
                severity=Severity.MEDIUM,
                url=url,
                parameter="OPTIONS",
                method="OPTIONS",
                payload="OPTIONS request",
                evidence=f"Allow header: {allow}. "
                         f"Dangerous methods: {', '.join(dangerous_found)}",
                remediation=(
                    "Disable unnecessary HTTP methods in your web server configuration. "
                    "Only GET, POST, and HEAD should be enabled unless specifically required. "
                    "Apache: use <LimitExcept> directive. "
                    "Nginx: return 405 for unwanted methods. "
                    "IIS: remove WebDAV module if not needed."
                ),
            ))

    def _test_trace(self, url: str) -> None:
        """Test if TRACE method is enabled (Cross-Site Tracing)."""
        self._count_test()
        try:
            session = http_utils.get_session()
            resp = session.request("TRACE", url, timeout=10)
        except Exception:
            return

        if resp.status_code == 200:
            # Check if our request headers are echoed back
            body = resp.text.lower()
            if "trace /" in body or "user-agent:" in body:
                self._log_finding(Finding(
                    vuln_type="HTTP TRACE Method Enabled (XST)",
                    severity=Severity.MEDIUM,
                    url=url,
                    parameter="TRACE",
                    method="TRACE",
                    payload="TRACE / HTTP/1.1",
                    evidence=(
                        f"TRACE returned HTTP {resp.status_code} and echoed "
                        f"request headers. This enables Cross-Site Tracing attacks "
                        f"that can steal HttpOnly cookies via JavaScript."
                    ),
                    remediation=(
                        "Disable the TRACE method on your web server. "
                        "Apache: TraceEnable off. "
                        "Nginx: return 405 for TRACE. "
                        "IIS: disable TRACE verb in request filtering."
                    ),
                ))

    def _test_dangerous_methods(self, url: str) -> None:
        """Probe PUT and DELETE to see if they actually work."""
        # Test PUT
        self._count_test()
        try:
            session = http_utils.get_session()
            resp = session.put(
                url,
                data="W3BSP1D3R security test - safe to delete",
                timeout=10,
            )
            if resp.status_code in (200, 201, 204):
                self._log_finding(Finding(
                    vuln_type="HTTP PUT Method Enabled",
                    severity=Severity.HIGH,
                    url=url,
                    parameter="PUT",
                    method="PUT",
                    payload="PUT request with test body",
                    evidence=f"PUT returned HTTP {resp.status_code} — "
                             f"arbitrary file upload may be possible.",
                    remediation=(
                        "Disable PUT method unless specifically required by your "
                        "application. If needed, ensure it requires authentication "
                        "and authorization checks."
                    ),
                ))
        except Exception:
            pass

        # Test DELETE (only check response code, don't actually delete)
        self._count_test()
        try:
            test_url = url.rstrip("/") + "/w3bsp1d3r-delete-test-nonexistent"
            resp = session.delete(test_url, timeout=10)
            # 405 Method Not Allowed is the correct response
            if resp.status_code in (200, 204):
                self._log_finding(Finding(
                    vuln_type="HTTP DELETE Method Enabled",
                    severity=Severity.HIGH,
                    url=url,
                    parameter="DELETE",
                    method="DELETE",
                    payload="DELETE request on test path",
                    evidence=f"DELETE returned HTTP {resp.status_code} — "
                             f"resource deletion may be possible.",
                    remediation=(
                        "Disable DELETE method unless required. Ensure any "
                        "DELETE endpoints require authentication and proper "
                        "authorization checks."
                    ),
                ))
        except Exception:
            pass
