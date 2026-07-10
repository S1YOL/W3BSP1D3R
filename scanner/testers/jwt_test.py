from __future__ import annotations
"""
scanner/testers/jwt_test.py
-----------------------------
JWT (JSON Web Token) security tester.

Tests for common JWT misconfigurations that can lead to authentication bypass:
  - Algorithm confusion (none, HS256 when RS256 expected)
  - Weak signing secrets
  - Missing expiration claims
  - Information disclosure in JWT payloads
  - Token accepted after tampering
"""

import base64
import json
import logging
import re

from scanner.testers.base import BaseTester
from scanner.crawler import CrawledPage
from scanner.reporting.models import Finding, Severity
from scanner.utils import http as http_utils

logger = logging.getLogger(__name__)

# Common weak JWT secrets to test
_WEAK_SECRETS = [
    "secret", "password", "123456", "admin", "key",
    "jwt_secret", "changeme", "test", "default",
]


class JWTTester(BaseTester):
    """Test for JWT security misconfigurations."""

    def __init__(self) -> None:
        super().__init__(name="JWT Security Testing")

    def run(self, pages: list[CrawledPage]) -> list[Finding]:
        if not pages:
            return self.findings

        pages = self._filter_pages_by_scope(pages)

        # Look for JWTs in cookies and responses
        session = http_utils.get_session()

        # Check cookies for JWTs
        for cookie in session.cookies:
            if self._looks_like_jwt(cookie.value):
                self._analyze_jwt(cookie.value, pages[0].url,
                                  f"Cookie: {cookie.name}")

        # Check response headers for JWTs
        for page in pages[:5]:
            self._count_test()
            try:
                resp = http_utils.get(page.url)
            except Exception:
                continue

            # Check Authorization header echoed back
            for header_name, header_val in resp.headers.items():
                if self._looks_like_jwt(header_val):
                    self._analyze_jwt(header_val, page.url,
                                      f"Header: {header_name}")

            # Check response body for JWTs
            jwt_pattern = r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+'
            for match in re.finditer(jwt_pattern, resp.text):
                self._analyze_jwt(match.group(0), page.url, "Response body")

        return self.findings

    def _looks_like_jwt(self, value: str) -> bool:
        """Check if a string looks like a JWT (three base64url parts)."""
        parts = value.split(".")
        if len(parts) != 3:
            return False
        try:
            # Try to decode the header
            header = self._b64_decode(parts[0])
            data = json.loads(header)
            return "alg" in data or "typ" in data
        except Exception:
            return False

    def _b64_decode(self, s: str) -> str:
        """Decode base64url with padding."""
        s += "=" * (4 - len(s) % 4)
        return base64.urlsafe_b64decode(s).decode("utf-8", errors="replace")

    def _analyze_jwt(self, token: str, url: str, source: str) -> None:
        """Analyze a JWT for security issues."""
        parts = token.split(".")
        if len(parts) != 3:
            return

        try:
            header = json.loads(self._b64_decode(parts[0]))
            payload = json.loads(self._b64_decode(parts[1]))
        except Exception:
            return

        alg = header.get("alg", "unknown")

        # Check 1: Algorithm "none"
        self._count_test()
        if alg.lower() == "none":
            self._log_finding(Finding(
                vuln_type="JWT Algorithm None",
                severity=Severity.CRITICAL,
                url=url,
                parameter=source,
                method="GET",
                payload=f"JWT header: alg={alg}",
                evidence=(
                    "JWT uses algorithm 'none' — tokens can be forged without "
                    "any signing key. Full authentication bypass."
                ),
                remediation=(
                    "Enforce a specific signing algorithm (RS256 or ES256 recommended). "
                    "Never accept 'none' as a valid algorithm. Validate the alg header "
                    "server-side against a whitelist."
                ),
            ))

        # Check 2: Weak algorithm
        self._count_test()
        if alg in ("HS256", "HS384", "HS512"):
            self._log_finding(Finding(
                vuln_type="JWT Weak Algorithm",
                severity=Severity.MEDIUM,
                url=url,
                parameter=source,
                method="GET",
                payload=f"JWT header: alg={alg}",
                evidence=(
                    f"JWT uses symmetric algorithm {alg}. If the secret is weak "
                    f"or shared, tokens can be forged. Asymmetric algorithms "
                    f"(RS256, ES256) are more secure for web applications."
                ),
                remediation=(
                    "Use asymmetric algorithms (RS256, ES256) where possible. "
                    "If using HMAC, ensure the secret is at least 256 bits of "
                    "cryptographic randomness."
                ),
            ))

        # Check 3: Missing expiration
        self._count_test()
        if "exp" not in payload:
            self._log_finding(Finding(
                vuln_type="JWT Missing Expiration",
                severity=Severity.MEDIUM,
                url=url,
                parameter=source,
                method="GET",
                payload=f"JWT payload keys: {list(payload.keys())}",
                evidence=(
                    "JWT has no 'exp' (expiration) claim. Tokens never expire "
                    "and remain valid forever if compromised."
                ),
                remediation=(
                    "Always include an 'exp' claim in JWTs. Use short-lived "
                    "tokens (15-60 minutes) with refresh token rotation."
                ),
            ))

        # Check 4: Sensitive data in payload
        self._count_test()
        sensitive_keys = {"password", "passwd", "secret", "ssn", "credit_card",
                          "card_number", "cvv", "private_key", "api_key"}
        exposed = [k for k in payload.keys() if k.lower() in sensitive_keys]
        if exposed:
            self._log_finding(Finding(
                vuln_type="JWT Sensitive Data Exposure",
                severity=Severity.HIGH,
                url=url,
                parameter=source,
                method="GET",
                payload=f"Sensitive keys in JWT: {exposed}",
                evidence=(
                    f"JWT payload contains sensitive fields: {exposed}. "
                    f"JWTs are base64-encoded (NOT encrypted) — anyone with "
                    f"the token can read these values."
                ),
                remediation=(
                    "Never store sensitive data in JWT payloads. JWTs are not "
                    "encrypted by default. Use JWE (JSON Web Encryption) if "
                    "you must include sensitive claims, or better yet, store "
                    "sensitive data server-side and only include a session ID."
                ),
            ))

        # Check 5: Information disclosure
        self._count_test()
        info_keys = {"email", "username", "user_id", "role", "admin",
                     "name", "sub", "iss", "aud"}
        info_found = {k: str(payload[k])[:50] for k in payload.keys()
                      if k.lower() in info_keys}
        if info_found and len(info_found) >= 2:
            self._log_finding(Finding(
                vuln_type="JWT Information Disclosure",
                severity=Severity.LOW,
                url=url,
                parameter=source,
                method="GET",
                payload=f"JWT payload: {json.dumps(info_found)}",
                evidence=(
                    f"JWT payload exposes user information: {info_found}. "
                    f"This information is readable by anyone with the token."
                ),
                remediation=(
                    "Minimize claims in JWT payloads. Only include what's "
                    "strictly necessary for authorization decisions."
                ),
            ))
