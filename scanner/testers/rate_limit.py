from __future__ import annotations
"""
scanner/testers/rate_limit.py
-------------------------------
Rate limiting and brute force protection tester.

Tests whether critical endpoints (login, API, password reset) have
proper rate limiting to prevent:
  - Credential brute force attacks
  - Account enumeration
  - API abuse / denial of service
  - Password reset flooding

Detection approach:
  - Sends rapid sequential requests to login/auth endpoints
  - Checks if the server ever returns 429, blocks, or CAPTCHAs
  - Tests both form-based and API endpoints
"""

import logging
import secrets
import time
from urllib.parse import urlparse

from scanner.testers.base import BaseTester
from scanner.crawler import CrawledPage
from scanner.reporting.models import Finding, Severity
from scanner.utils import http as http_utils

logger = logging.getLogger(__name__)

# Number of rapid requests to send (enough to trigger rate limiting
# on well-configured systems, not enough to cause actual disruption)
_RAPID_REQUESTS = 10

# Known login/auth endpoint patterns
_AUTH_PATTERNS = [
    "login", "signin", "sign-in", "auth", "authenticate",
    "session", "token", "oauth", "api/login", "api/auth",
    "wp-login", "admin/login", "user/login",
]

# Reset/sensitive endpoint patterns
_SENSITIVE_PATTERNS = [
    "password", "reset", "forgot", "recover", "register",
    "signup", "sign-up", "api/user", "api/account",
]


class RateLimitTester(BaseTester):
    """Test for missing rate limiting on authentication and sensitive endpoints."""

    def __init__(self) -> None:
        super().__init__(name="Rate Limit Testing")

    def run(self, pages: list[CrawledPage]) -> list[Finding]:
        if not pages:
            return self.findings

        pages = self._filter_pages_by_scope(pages)
        tested_urls = set()

        # Find login/auth forms
        for page in pages:
            url_lower = page.url.lower()

            # Check if this is a login/auth page
            is_auth = any(p in url_lower for p in _AUTH_PATTERNS)
            is_sensitive = any(p in url_lower for p in _SENSITIVE_PATTERNS)

            if is_auth or is_sensitive:
                if page.url not in tested_urls:
                    tested_urls.add(page.url)
                    self._test_rate_limit(page, is_auth)

            # Check forms for login-like fields
            for form in page.forms:
                has_password = any(f.field_type == "password" for f in form.fields)
                if has_password and form.action_url not in tested_urls:
                    tested_urls.add(form.action_url)
                    self._test_form_rate_limit(form)

        # Test common auth endpoints even if not crawled
        if pages:
            parsed = urlparse(pages[0].url)
            origin = f"{parsed.scheme}://{parsed.netloc}"
            for pattern in ["/login", "/api/login", "/api/auth/login",
                            "/auth/token", "/oauth/token"]:
                endpoint = origin + pattern
                if endpoint not in tested_urls:
                    self._test_endpoint_rate_limit(endpoint)

        return self.findings

    def _test_rate_limit(self, page: CrawledPage, is_auth: bool) -> None:
        """Test rate limiting on a page by sending rapid GET requests."""
        self._count_test()
        blocked = False

        for i in range(_RAPID_REQUESTS):
            try:
                resp = http_utils.get(page.url)
                if resp.status_code == 429:
                    blocked = True
                    break
                if resp.status_code == 403 and i > 3:
                    blocked = True
                    break
                # Check for CAPTCHA
                if "captcha" in resp.text.lower() or "recaptcha" in resp.text.lower():
                    blocked = True
                    break
            except Exception:
                blocked = True
                break

        if not blocked:
            severity = Severity.MEDIUM if is_auth else Severity.LOW
            endpoint_type = "authentication" if is_auth else "sensitive"

            self._log_finding(Finding(
                vuln_type=f"Missing Rate Limiting ({endpoint_type} endpoint)",
                severity=severity,
                url=page.url,
                parameter="Rate limit",
                method="GET",
                payload=f"{_RAPID_REQUESTS} rapid requests without blocking",
                evidence=(
                    f"Sent {_RAPID_REQUESTS} rapid requests to {endpoint_type} "
                    f"endpoint without receiving HTTP 429, CAPTCHA, or block. "
                    f"This allows brute force attacks."
                ),
                remediation=(
                    "Implement rate limiting on authentication and sensitive endpoints. "
                    "Use progressive delays, account lockout after N failed attempts, "
                    "and CAPTCHA challenges. Consider tools like fail2ban, "
                    "Cloudflare Rate Limiting, or application-level throttling. "
                    "Recommended: max 5-10 attempts per minute for login endpoints."
                ),
            ))

    def _test_form_rate_limit(self, form) -> None:
        """Test rate limiting on a login form by sending rapid POST requests."""
        self._count_test()
        blocked = False

        # Build fake login data
        data = {}
        for field in form.fields:
            if field.field_type == "password":
                data[field.name] = "w3bsp1d3r_test_password"
            elif field.field_type in ("text", "email"):
                data[field.name] = "w3bsp1d3r_test_user"
            else:
                data[field.name] = field.value

        for i in range(_RAPID_REQUESTS):
            try:
                resp = http_utils.post(form.action_url, data=data)
                if resp.status_code == 429:
                    blocked = True
                    break
                if "captcha" in resp.text.lower():
                    blocked = True
                    break
                if resp.status_code == 403 and i > 3:
                    blocked = True
                    break
            except Exception:
                blocked = True
                break

        if not blocked:
            self._log_finding(Finding(
                vuln_type="Missing Rate Limiting (login form)",
                severity=Severity.MEDIUM,
                url=form.action_url,
                parameter="Login form",
                method="POST",
                payload=f"{_RAPID_REQUESTS} rapid login attempts",
                evidence=(
                    f"Submitted {_RAPID_REQUESTS} rapid login attempts to "
                    f"{form.action_url} without rate limiting. "
                    f"Credential brute force attacks are possible."
                ),
                remediation=(
                    "Implement rate limiting on login forms. After 5 failed "
                    "attempts, require CAPTCHA or lock the account temporarily. "
                    "Log all failed login attempts for monitoring."
                ),
            ))

    def _soft_404_fingerprint(self, origin: str) -> tuple[int, int] | None:
        """Fetch a random non-existent path to fingerprint the server's
        'not found' behaviour (status code + rough body length). Servers that
        return 200 for unknown paths (SPA catch-alls) are the reason the old
        'not 404/405 == exists' logic produced false positives."""
        try:
            rand = f"/w3bsp1d3r-{secrets.token_hex(8)}-notfound"
            resp = http_utils.get(origin + rand)
            return resp.status_code, len(resp.content)
        except Exception:
            return None

    def _looks_like_soft_404(self, resp, fingerprint: tuple[int, int] | None) -> bool:
        """True if a response is indistinguishable from the soft-404 baseline."""
        if fingerprint is None:
            return False
        base_status, base_len = fingerprint
        if resp.status_code != base_status:
            return False
        # Same status as the not-found baseline and near-identical size → catch-all
        return abs(len(resp.content) - base_len) <= max(64, base_len * 0.05)

    def _test_endpoint_rate_limit(self, url: str) -> None:
        """Quick test if a known auth endpoint exists and has rate limiting."""
        self._count_test()
        parsed = urlparse(url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        fingerprint = self._soft_404_fingerprint(origin)
        try:
            resp = http_utils.get(url)
            if resp.status_code in (404, 405):
                return  # Endpoint doesn't exist
            # Guard against SPA/catch-all servers that return 200 for everything:
            # if the endpoint response is indistinguishable from a random
            # non-existent path, it is not a real endpoint.
            if self._looks_like_soft_404(resp, fingerprint):
                logger.debug("Skipping %s — matches soft-404 baseline", url)
                return
        except Exception:
            return

        # Endpoint exists — test rate limiting
        blocked = False
        for i in range(_RAPID_REQUESTS):
            try:
                resp = http_utils.post(url, data={"username": "test", "password": "test"})
                if resp.status_code == 429:
                    blocked = True
                    break
            except Exception:
                blocked = True
                break

        if not blocked:
            self._log_finding(Finding(
                vuln_type="Missing Rate Limiting (API auth endpoint)",
                severity=Severity.MEDIUM,
                url=url,
                parameter="API endpoint",
                method="POST",
                payload=f"{_RAPID_REQUESTS} rapid API requests",
                evidence=(
                    f"API auth endpoint {url} accepts rapid requests without "
                    f"rate limiting or blocking."
                ),
                remediation=(
                    "Implement rate limiting on API authentication endpoints. "
                    "Use token bucket or sliding window algorithms. "
                    "Return HTTP 429 with Retry-After header when limit is exceeded."
                ),
            ))
