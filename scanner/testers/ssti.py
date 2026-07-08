from __future__ import annotations
"""
scanner/testers/ssti.py
------------------------
Server-Side Template Injection (SSTI) detection.

Security concept:
  SSTI occurs when user input is embedded directly into a server-side
  template engine (Jinja2, Freemarker, Mako, ERB, Twig, Velocity, etc.)
  without proper sanitisation. Successful SSTI can lead to Remote Code
  Execution (RCE) — the highest severity vulnerability.

Detection strategy:
  1. Inject mathematical expressions unique to each template engine
  2. Check if the response contains the computed result (not the raw expression)
  3. If the expression is evaluated, the template engine is processing user input
  4. Use engine-specific markers to identify which engine is vulnerable

Example: injecting {{7*7}} into a Jinja2 template returns 49 in the response.

OWASP ref: A03:2021 Injection
"""

import logging
import secrets

from scanner.crawler import CrawledPage, CrawledForm
from scanner.reporting.models import Finding, Severity, VulnType
from scanner.testers.base import BaseTester
from scanner.utils import http as http_utils

logger = logging.getLogger(__name__)

# Each probe is (engine_name, build_payload_fn, description)
# We don't use .format() because template syntax ({{}}, ${}) conflicts with
# Python's format strings. Instead, each probe builds the payload directly.


def _build_probes(a: int, b: int) -> list[tuple[str, str]]:
    """
    Build (payload, engine_name) pairs for the given random integers.
    Returns a list of (payload_string, engine_name) tuples.
    """
    return [
        # Jinja2 / Twig / Django:  {{a*b}}
        (f"{{{{{a}*{b}}}}}", "Jinja2/Twig"),
        # Freemarker / Mako:  ${a*b}
        (f"${{{a}*{b}}}", "Freemarker/Mako"),
        # ERB (Ruby):  <%=a*b%>
        (f"<%={a}*{b}%>", "ERB (Ruby)"),
        # Smarty:  {a*b}  (single brace)
        (f"{{{a}*{b}}}", "Smarty"),
        # Pebble:  {{a*b}}  (same as Jinja2)
        (f"{{{{{a}*{b}}}}}", "Pebble"),
    ]

_REMEDIATION = (
    "Never embed raw user input directly into template strings. Use the template "
    "engine's built-in auto-escaping and sandboxing features. Pass user input as "
    "template variables, not as part of the template source code. "
    "For Jinja2: use the SandboxedEnvironment. For Freemarker: disable new_builtin_class_resolver. "
    "See: https://portswigger.net/web-security/server-side-template-injection"
)


class SSTITester(BaseTester):
    """Detects Server-Side Template Injection vulnerabilities."""

    def __init__(self) -> None:
        super().__init__(name="SSTI Tester")

    def run(self, pages: list[CrawledPage]) -> list[Finding]:
        self.findings.clear()
        self._params_tested = 0

        for page in pages:
            # Test form fields
            for form in page.forms:
                for field in form.testable_fields:
                    self._test_form(form, field.name, page.url)

            # Test GET parameters
            for param_name in page.get_params:
                self._test_get(page.url, param_name)

        return self.findings

    def _test_form(self, form: CrawledForm, field_name: str, page_url: str) -> None:
        """Inject SSTI probes into a form field."""
        self._count_test()

        a = secrets.randbelow(89) + 10  # 10-98
        b = secrets.randbelow(89) + 10
        expected = str(a * b)

        for payload, engine in _build_probes(a, b):
            data = self._inject_form(form, field_name, payload)
            try:
                resp = http_utils.post(form.action_url, data=data)
            except Exception:
                continue

            if expected in resp.text and payload not in resp.text:
                self._log_finding(Finding(
                    vuln_type=VulnType.SSTI,
                    severity=Severity.CRITICAL,
                    url=form.action_url,
                    parameter=field_name,
                    method="POST",
                    payload=payload,
                    evidence=(
                        f"Template engine ({engine}) evaluated the expression: "
                        f"{a}*{b} = {expected}. The computed result appeared in the "
                        f"response without the raw template syntax, confirming SSTI. "
                        f"This typically leads to Remote Code Execution."
                    ),
                    remediation=_REMEDIATION,
                    extra={"engine": engine, "expression": f"{a}*{b}", "result": a * b},
                ))
                return  # One finding per field is enough

    def _test_get(self, url: str, param_name: str) -> None:
        """Inject SSTI probes into a GET parameter."""
        self._count_test()

        a = secrets.randbelow(89) + 10
        b = secrets.randbelow(89) + 10
        expected = str(a * b)

        for payload, engine in _build_probes(a, b):
            test_url = self._inject_get_param(url, param_name, payload)
            try:
                resp = http_utils.get(test_url)
            except Exception:
                continue

            if expected in resp.text and payload not in resp.text:
                self._log_finding(Finding(
                    vuln_type=VulnType.SSTI,
                    severity=Severity.CRITICAL,
                    url=url,
                    parameter=param_name,
                    method="GET",
                    payload=payload,
                    evidence=(
                        f"Template engine ({engine}) evaluated the expression: "
                        f"{a}*{b} = {expected}. The computed result appeared in the "
                        f"response, confirming Server-Side Template Injection. "
                        f"This typically leads to Remote Code Execution."
                    ),
                    remediation=_REMEDIATION,
                    extra={"engine": engine, "expression": f"{a}*{b}", "result": a * b},
                ))
                return
