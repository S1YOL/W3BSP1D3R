from __future__ import annotations
"""
scanner/testers/open_redirect.py
-----------------------------------
Open Redirect vulnerability tester.

An open redirect lets attackers craft URLs on trusted domains that redirect
visitors to malicious sites. Used in phishing, OAuth token theft, and
bypassing referer checks.

Detection: inject a known external domain as the redirect target value into
parameters whose names suggest redirect behavior (redirect_to, next, return,
goto, url, etc.), then check whether the response:
  a) Contains a 3xx Location header pointing to our domain, OR
  b) Reflects our domain in a meta-refresh or JavaScript redirect.

OWASP ref: A01:2021 Broken Access Control, CWE-601
"""

import logging
from urllib.parse import urlparse

from scanner.crawler import CrawledForm, CrawledPage
from scanner.reporting.models import Finding, Severity, VulnType
from scanner.testers.base import BaseTester
from scanner.utils import http as http_utils

logger = logging.getLogger(__name__)

_REMEDIATION = (
    "Validate redirect targets against a strict allowlist of permitted domains. "
    "For internal redirects, use relative paths only. Never redirect to a "
    "user-supplied URL without explicit allowlist validation. "
    "Ref: OWASP Unvalidated Redirects and Forwards Cheat Sheet."
)

# A domain that is clearly external and cannot be confused with localhost
_CANARY_DOMAIN = "open-redirect-test.example.com"

_PAYLOADS = [
    f"https://{_CANARY_DOMAIN}",
    f"//{_CANARY_DOMAIN}",
    f"https://{_CANARY_DOMAIN}/%2F..",
    f"https://{_CANARY_DOMAIN}?trusted=1",
    f"https://{_CANARY_DOMAIN}#bypass",
    f"/%09//{_CANARY_DOMAIN}",          # tab-separated bypass
    f"/\\{_CANARY_DOMAIN}",             # backslash bypass
]

# Parameter names that commonly hold redirect targets
_REDIRECT_PARAMS = {
    "redirect", "redirect_to", "redirect_uri", "redirect_url",
    "return", "return_to", "return_url",
    "next", "next_url",
    "goto", "go",
    "url", "target", "dest", "destination",
    "redir", "ref", "out",
    "continue", "callback",
    "forward", "location",
    "link", "href", "path",
}


class OpenRedirectTester(BaseTester):
    """Tests for open redirect vulnerabilities in URL parameters and form fields."""

    def __init__(self) -> None:
        super().__init__(name="Open Redirect Tester")

    def run(self, pages: list[CrawledPage]) -> list[Finding]:
        self.findings.clear()
        self._params_tested = 0

        for page in pages:
            for param in page.get_params:
                if param.lower() in _REDIRECT_PARAMS:
                    self._test_get(page.url, param)
            for form in page.forms:
                for field in form.testable_fields:
                    if field.name.lower() in _REDIRECT_PARAMS:
                        self._test_form(form, field.name)

        return self.findings

    def _test_get(self, url: str, param_name: str) -> None:
        self._count_test()
        for payload in _PAYLOADS:
            injected = self._inject_get_param(url, param_name, payload)
            try:
                resp = http_utils.get(injected, allow_redirects=False)
            except Exception:
                continue

            if self._is_open_redirect(resp):
                self._log_finding(Finding(
                    vuln_type=VulnType.OPEN_REDIRECT,
                    severity=Severity.MEDIUM,
                    url=url,
                    parameter=param_name,
                    method="GET",
                    payload=payload,
                    evidence=self._evidence(resp),
                    remediation=_REMEDIATION,
                ))
                return

    def _test_form(self, form: CrawledForm, field_name: str) -> None:
        self._count_test()
        for payload in _PAYLOADS:
            data = self._inject_form(form, field_name, payload)
            try:
                if form.method == "POST":
                    resp = http_utils.post(form.action_url, data=data, allow_redirects=False)
                else:
                    resp = http_utils.get(form.action_url, params=data, allow_redirects=False)
            except Exception:
                continue

            if self._is_open_redirect(resp):
                self._log_finding(Finding(
                    vuln_type=VulnType.OPEN_REDIRECT,
                    severity=Severity.MEDIUM,
                    url=form.action_url,
                    parameter=field_name,
                    method=form.method,
                    payload=payload,
                    evidence=self._evidence(resp),
                    remediation=_REMEDIATION,
                ))
                return

    def _is_open_redirect(self, resp) -> bool:
        if resp.status_code in (301, 302, 303, 307, 308):
            loc = resp.headers.get("Location", "")
            if _CANARY_DOMAIN in loc:
                return True
        # JavaScript / meta-refresh redirect in body
        if _CANARY_DOMAIN in resp.text:
            return True
        return False

    def _evidence(self, resp) -> str:
        if resp.status_code in (301, 302, 303, 307, 308):
            return (f"HTTP {resp.status_code} redirect — "
                    f"Location: {resp.headers.get('Location', '?')}")
        return f"Canary domain '{_CANARY_DOMAIN}' reflected in response body"
