from __future__ import annotations
"""
scanner/testers/headers.py
----------------------------
HTTP security response headers tester.

Checks for the presence and correct configuration of headers that enterprise
scanners like Acunetix, Burp Suite Pro, and Qualys flag in every audit.

Headers checked:
  - Content-Security-Policy (CSP) + unsafe-inline / unsafe-eval detection
  - Strict-Transport-Security (HSTS) — HTTPS targets only
  - X-Frame-Options / CSP frame-ancestors (clickjacking)
  - X-Content-Type-Options
  - Referrer-Policy
  - Permissions-Policy
  - Server / X-Powered-By version disclosure

OWASP ref: A05:2021 Security Misconfiguration
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
    "Configure all recommended security headers in your web server or application. "
    "Validate your headers at securityheaders.com. "
    "Ref: OWASP Secure Headers Project — https://owasp.org/www-project-secure-headers/"
)


class HeadersTester(BaseTester):
    """Tests for missing or misconfigured HTTP security response headers."""

    def __init__(self) -> None:
        super().__init__(name="Security Headers Tester")

    def run(self, pages: list[CrawledPage]) -> list[Finding]:
        self.findings.clear()
        self._params_tested = 0

        # Only check one URL per unique path to avoid redundant requests
        seen: set[str] = set()
        for page in pages:
            parsed = urlparse(page.url)
            key = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            if key in seen:
                continue
            seen.add(key)
            self._check(page.url)

        return self.findings

    def _check(self, url: str) -> None:
        self._count_test()
        try:
            resp = http_utils.get(url)
        except Exception:
            return

        h = {k.lower(): v for k, v in resp.headers.items()}
        https = url.startswith("https://")

        # --- Content-Security-Policy ---
        if "content-security-policy" not in h:
            self._flag(url, "Missing Content-Security-Policy (CSP)",
                       Severity.MEDIUM,
                       "No CSP header found. CSP prevents XSS by declaring approved "
                       "content sources. Set a strict policy.")
        else:
            csp = h["content-security-policy"].lower()
            # Only flag unsafe-inline in script-src (not style-src, which is low risk)
            script_src_unsafe = False
            if "script-src" in csp:
                # Extract the script-src directive value
                for directive in csp.split(";"):
                    if "script-src" in directive and "unsafe-inline" in directive:
                        script_src_unsafe = True
                        break
            elif "default-src" in csp and "unsafe-inline" in csp and "script-src" not in csp:
                # No explicit script-src, so default-src applies to scripts
                for directive in csp.split(";"):
                    if "default-src" in directive and "unsafe-inline" in directive:
                        script_src_unsafe = True
                        break
            if script_src_unsafe:
                self._flag(url, "Weak CSP: 'unsafe-inline' allows inline scripts",
                           Severity.MEDIUM,
                           f"CSP script-src contains 'unsafe-inline' which defeats XSS protection. "
                           f"Value: {h['content-security-policy'][:200]}")
            if "unsafe-eval" in csp:
                self._flag(url, "Weak CSP: 'unsafe-eval' allows eval() execution",
                           Severity.MEDIUM,
                           f"CSP contains 'unsafe-eval' which permits dynamic code execution. "
                           f"Value: {h['content-security-policy'][:200]}")

        # --- HSTS (HTTPS only) ---
        if https and "strict-transport-security" not in h:
            self._flag(url, "Missing Strict-Transport-Security (HSTS)",
                       Severity.MEDIUM,
                       "HSTS not set on HTTPS site. Without HSTS, browsers may accept "
                       "HTTP connections, enabling downgrade and MitM attacks.")
        elif https and "strict-transport-security" in h:
            hsts = h["strict-transport-security"].lower()
            if "max-age" not in hsts:
                self._flag(url, "Malformed HSTS header (no max-age)",
                           Severity.MEDIUM,
                           f"HSTS header missing max-age directive: {h['strict-transport-security']}")
            elif "max-age=0" in hsts:
                self._flag(url, "HSTS max-age=0 effectively disables HSTS",
                           Severity.MEDIUM,
                           f"HSTS value: {h['strict-transport-security']}")

        # --- Clickjacking (X-Frame-Options or CSP frame-ancestors) ---
        has_xfo = "x-frame-options" in h
        has_frame_ancestors = "frame-ancestors" in h.get("content-security-policy", "").lower()
        if not has_xfo and not has_frame_ancestors:
            self._flag(url, "Missing X-Frame-Options / CSP frame-ancestors (clickjacking risk)",
                       Severity.MEDIUM,
                       "No clickjacking protection found. Attackers can embed this page "
                       "in a hidden iframe to trick users into unintended clicks.")

        # --- X-Content-Type-Options ---
        if "x-content-type-options" not in h:
            self._flag(url, "Missing X-Content-Type-Options",
                       Severity.LOW,
                       "X-Content-Type-Options: nosniff not set. Browsers may MIME-sniff "
                       "responses and execute uploaded files as scripts.")
        elif h["x-content-type-options"].lower().strip() != "nosniff":
            self._flag(url, f"X-Content-Type-Options has unexpected value: {h['x-content-type-options']}",
                       Severity.LOW,
                       "Expected 'nosniff', got a different value.")

        # --- Referrer-Policy ---
        if "referrer-policy" not in h:
            self._flag(url, "Missing Referrer-Policy",
                       Severity.LOW,
                       "Referrer-Policy not set. Sensitive URL fragments may leak to "
                       "third-party sites via the Referer header.")

        # --- Permissions-Policy ---
        if "permissions-policy" not in h and "feature-policy" not in h:
            self._flag(url, "Missing Permissions-Policy",
                       Severity.LOW,
                       "Permissions-Policy not set. This header restricts access to "
                       "browser features (camera, microphone, geolocation).")

        # --- Server version disclosure ---
        if "server" in h:
            val = h["server"]
            if re.search(r"\d+[\.\d]", val):
                self._flag(url, f"Server header discloses version: {val}",
                           Severity.LOW,
                           f"The Server header reveals software version: '{val}'. "
                           "Attackers use this to target known CVEs for that version.")

        # --- X-Powered-By disclosure ---
        if "x-powered-by" in h:
            self._flag(url, f"X-Powered-By discloses tech stack: {h['x-powered-by']}",
                       Severity.LOW,
                       f"X-Powered-By: {h['x-powered-by']} reveals the server-side framework. "
                       "Remove this header from your web server configuration.")

        # --- Cache-Control on sensitive pages ---
        if "cache-control" not in h:
            self._flag(url, "Missing Cache-Control header",
                       Severity.LOW,
                       "No Cache-Control header. Sensitive responses may be cached by "
                       "browsers or intermediary proxies.")

    def _flag(self, url: str, title: str, severity: str, evidence: str) -> None:
        self._log_finding(Finding(
            vuln_type=VulnType.SECURITY_HEADER,
            severity=severity,
            url=url,
            parameter="HTTP Response Headers",
            method="GET",
            payload="(header inspection — no payload sent)",
            evidence=f"{title}: {evidence}",
            remediation=_REMEDIATION,
        ))
