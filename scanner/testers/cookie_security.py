from __future__ import annotations
"""
scanner/testers/cookie_security.py
------------------------------------
Cookie security attribute validation.

Security concept:
  Cookies are the primary mechanism for maintaining session state. If cookies
  lack proper security attributes, they're vulnerable to theft, fixation,
  and cross-site attacks:
  - Missing HttpOnly → XSS can steal session cookies via document.cookie
  - Missing Secure → cookies sent over plain HTTP, enabling MitM interception
  - Missing SameSite → CSRF attacks can send authenticated requests cross-origin
  - Overly broad Domain/Path → cookies leak to subdomains or unrelated paths

This tester inspects Set-Cookie headers on every crawled page and flags
insecure cookie configurations.

OWASP ref: A07:2021 Identification and Authentication Failures
"""

import logging
import re
from urllib.parse import urlparse

from scanner.crawler import CrawledPage
from scanner.reporting.models import Finding, Severity, VulnType
from scanner.testers.base import BaseTester
from scanner.utils import http as http_utils

logger = logging.getLogger(__name__)

_REMEDIATION = (
    "Set HttpOnly, Secure, and SameSite attributes on all session and "
    "authentication cookies. Use SameSite=Lax at minimum (SameSite=Strict "
    "for sensitive cookies). Set the Secure flag on all cookies when the "
    "application is served over HTTPS. "
    "Ref: OWASP Session Management Cheat Sheet — "
    "https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html"
)

# Cookie names that are likely session/auth-related (case-insensitive patterns)
_SESSION_COOKIE_PATTERNS = re.compile(
    r"(sess|session|sid|token|auth|jwt|csrf|xsrf|login|user|"
    r"phpsessid|jsessionid|asp\.net_sessionid|connect\.sid|"
    r"laravel_session|_identity|remember_me|_csrf|csrftoken)",
    re.IGNORECASE,
)


class CookieSecurityTester(BaseTester):
    """Validates cookie security attributes (HttpOnly, Secure, SameSite)."""

    def __init__(self) -> None:
        super().__init__(name="Cookie Security Tester")

    def run(self, pages: list[CrawledPage]) -> list[Finding]:
        self.findings.clear()
        self._params_tested = 0

        # Deduplicate by URL
        seen_urls: set[str] = set()
        # Track cookies we've already flagged to avoid duplicates
        flagged_cookies: set[str] = set()

        for page in pages:
            parsed = urlparse(page.url)
            key = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            if key in seen_urls:
                continue
            seen_urls.add(key)

            self._check_cookies(page.url, flagged_cookies)

        return self.findings

    def _check_cookies(self, url: str, flagged_cookies: set[str]) -> None:
        """Fetch a URL and inspect all Set-Cookie headers."""
        self._count_test()

        try:
            resp = http_utils.get(url)
        except Exception:
            return

        is_https = url.startswith("https://")

        # The requests library merges Set-Cookie headers and provides cookie
        # objects via resp.cookies. We use raw headers when available for full
        # attribute inspection, falling back to the cookie jar.
        raw_cookies = []
        try:
            if hasattr(resp, 'raw') and hasattr(resp.raw, 'headers'):
                for header_name, header_value in resp.raw.headers.items():
                    if header_name.lower() == "set-cookie":
                        raw_cookies.append(header_value)
        except Exception:
            pass

        if raw_cookies:
            for cookie_str in raw_cookies:
                self._analyse_cookie_string(url, cookie_str, is_https, flagged_cookies)
        else:
            # Fallback: analyse cookies from the jar (less attribute detail)
            for cookie in resp.cookies:
                self._analyse_cookie_from_jar(url, cookie, is_https, flagged_cookies)

    def _analyse_cookie_from_jar(self, url: str, cookie, is_https: bool, flagged: set[str]) -> None:
        """Analyse a cookie from the requests cookie jar."""
        name = cookie.name
        if name in flagged:
            return

        is_session = bool(_SESSION_COOKIE_PATTERNS.search(name))
        if not is_session:
            return

        issues = []

        # Check HttpOnly via the _rest dict (how http.cookiejar stores it)
        rest = getattr(cookie, '_rest', {})
        has_httponly = (
            'HttpOnly' in rest
            or 'httponly' in rest
            or any(k.lower() == 'httponly' for k in rest)
        )
        if not has_httponly:
            issues.append(("Missing HttpOnly flag", Severity.HIGH,
                f"Cookie '{name}' lacks HttpOnly — JavaScript (document.cookie) can read it. "
                "XSS attacks can steal this session cookie."))

        if is_https and not cookie.secure:
            issues.append(("Missing Secure flag", Severity.HIGH,
                f"Cookie '{name}' lacks Secure flag on HTTPS site — the cookie "
                "will also be sent over plain HTTP, enabling MitM interception."))

        for title, severity, evidence in issues:
            flagged.add(name)
            self._log_finding(Finding(
                vuln_type=VulnType.COOKIE_SECURITY,
                severity=severity,
                url=url,
                parameter=f"Cookie: {name}",
                method="GET",
                payload="(cookie attribute inspection)",
                evidence=evidence,
                remediation=_REMEDIATION,
            ))

    def _analyse_cookie_string(self, url: str, cookie_str: str, is_https: bool, flagged: set[str]) -> None:
        """Analyse a raw Set-Cookie header string."""
        parts = [p.strip() for p in cookie_str.split(";")]
        if not parts:
            return

        # First part is name=value
        name_value = parts[0]
        if "=" not in name_value:
            return
        name = name_value.split("=", 1)[0].strip()

        if name in flagged:
            return

        is_session = bool(_SESSION_COOKIE_PATTERNS.search(name))
        if not is_session:
            return

        attrs_lower = [p.lower().strip() for p in parts[1:]]

        issues = []

        # Check HttpOnly
        if "httponly" not in attrs_lower:
            issues.append(("Missing HttpOnly", Severity.HIGH,
                f"Cookie '{name}' lacks HttpOnly — JavaScript can access it via "
                "document.cookie, making it vulnerable to XSS-based session theft."))

        # Check Secure (only flag on HTTPS sites)
        if is_https and not any("secure" == a for a in attrs_lower):
            issues.append(("Missing Secure flag", Severity.HIGH,
                f"Cookie '{name}' on HTTPS site lacks Secure flag — it will be sent "
                "over unencrypted HTTP connections, enabling MitM interception."))

        # Check SameSite
        has_samesite = any(a.startswith("samesite") for a in attrs_lower)
        if not has_samesite:
            issues.append(("Missing SameSite attribute", Severity.MEDIUM,
                f"Cookie '{name}' has no SameSite attribute. Without SameSite, the "
                "cookie is sent with cross-site requests, enabling CSRF attacks. "
                "Note: Chrome defaults to Lax, but other browsers may not."))
        else:
            samesite_val = ""
            for a in attrs_lower:
                if a.startswith("samesite"):
                    samesite_val = a.split("=", 1)[1].strip() if "=" in a else ""
            if samesite_val == "none" and not any("secure" == a for a in attrs_lower):
                issues.append(("SameSite=None without Secure", Severity.HIGH,
                    f"Cookie '{name}' has SameSite=None but no Secure flag. "
                    "Browsers will reject this cookie. SameSite=None requires Secure."))

        for title, severity, evidence in issues:
            flagged.add(name)
            self._log_finding(Finding(
                vuln_type=VulnType.COOKIE_SECURITY,
                severity=severity,
                url=url,
                parameter=f"Cookie: {name}",
                method="GET",
                payload="(Set-Cookie header inspection)",
                evidence=evidence,
                remediation=_REMEDIATION,
            ))
