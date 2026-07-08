from __future__ import annotations
"""
scanner/testers/nosql_injection.py
------------------------------------
NoSQL injection detection (MongoDB, CouchDB, etc.).

Security concept:
  NoSQL databases are vulnerable to injection attacks similar to SQL injection,
  but using different syntax. MongoDB is the most common target, where operator
  injection ($ne, $gt, $regex) or JavaScript injection (db.eval, $where) can
  bypass authentication and extract data.

Detection strategy:
  1. Inject MongoDB operator payloads into form fields and GET parameters
  2. Use boolean-based detection (true condition vs false condition)
  3. Check for MongoDB/NoSQL-specific error messages in responses
  4. Test for JavaScript injection in $where clauses

OWASP ref: A03:2021 Injection
"""

import logging

from scanner.crawler import CrawledPage, CrawledForm
from scanner.reporting.models import Finding, Severity, VulnType
from scanner.testers.base import BaseTester
from scanner.utils import http as http_utils

logger = logging.getLogger(__name__)

# MongoDB error signatures in responses
_NOSQL_ERROR_SIGNATURES = [
    "MongoError",
    "mongo",
    "MongoDB",
    "BSON",
    "$err",
    "BSONObj",
    "mongod",
    "MongoNetworkError",
    "MongooseError",
    "CastError",
    "ValidationError",
    "E11000",
    "WriteResult",
    "Mongo ServerError",
    "not master",
    "ns not found",
    "bad query",
    "no such cmd",
    "unrecognized expression",
    "unterminated subexpression",
    "SyntaxError: Unexpected token",
    "CouchDB",
    "database_does_not_exist",
    "Redis",
    "WRONGTYPE",
]

# Boolean-based NoSQL injection payloads
# Format: (true_payload, false_payload, description)
_BOOLEAN_PAYLOADS: list[tuple[str, str, str]] = [
    # MongoDB operator injection (JSON/object form)
    ('{"$ne":""}', '{"$eq":"__NOSQLTEST_IMPOSSIBLE_VALUE__"}', "MongoDB $ne operator"),
    ('{"$gt":""}', '{"$lt":""}', "MongoDB $gt/$lt operator"),
    ('{"$regex":".*"}', '{"$regex":"^$IMPOSSIBLE$"}', "MongoDB $regex operator"),
]

# Error-based NoSQL payloads (trigger MongoDB errors)
_ERROR_PAYLOADS: list[tuple[str, str]] = [
    ("'\"\\;{}()$", "Special characters for NoSQL syntax errors"),
    ('{"$gt":""}', "MongoDB $gt operator injection"),
    ("[$ne]=1", "MongoDB array operator injection"),
    ("true, $where: '1 == 1'", "MongoDB $where JavaScript injection"),
    ('{"$where":"sleep(100)"}', "MongoDB $where sleep injection"),
    ("{$ne: null}", "MongoDB $ne null injection"),
]

# GET parameter manipulation payloads (bracket notation)
_GET_PAYLOADS: list[tuple[str, str, str]] = [
    # These are appended to the parameter name: param[$ne]=1
    ("[$ne]=1", "[$eq]=__NOSQLTEST_IMPOSSIBLE__", "MongoDB bracket $ne operator"),
    ("[$gt]=", "[$lt]=", "MongoDB bracket $gt operator"),
    ("[$regex]=.*", "[$regex]=^$IMPOSSIBLE$", "MongoDB bracket $regex"),
]

_REMEDIATION = (
    "Use parameterised queries or the database driver's built-in sanitisation. "
    "For MongoDB: use the official driver's query builders instead of string "
    "concatenation. Validate and type-check all user input. Disable server-side "
    "JavaScript ($where, mapReduce) if not needed. "
    "Ref: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05.6-Testing_for_NoSQL_Injection"
)


class NoSQLInjectionTester(BaseTester):
    """Detects NoSQL injection vulnerabilities (MongoDB, CouchDB, etc.)."""

    # Minimum response body difference to flag boolean-based detection
    _BOOLEAN_DIFF_THRESHOLD = 50

    def __init__(self) -> None:
        super().__init__(name="NoSQL Injection Tester")

    def run(self, pages: list[CrawledPage]) -> list[Finding]:
        self.findings.clear()
        self._params_tested = 0

        for page in pages:
            # Test form fields
            for form in page.forms:
                for field in form.testable_fields:
                    self._test_form_error(form, field.name, page.url)
                    self._test_form_boolean(form, field.name, page.url)

            # Test GET parameters
            for param_name in page.get_params:
                self._test_get_error(page.url, param_name)
                self._test_get_boolean(page.url, param_name)

        return self.findings

    def _test_form_error(self, form: CrawledForm, field_name: str, page_url: str) -> None:
        """Inject NoSQL error payloads into form fields."""
        self._count_test()

        # Fetch baseline to avoid flagging errors already present in normal responses
        try:
            baseline_data = self._inject_form(form, field_name, "baseline_nosql_test")
            if form.method == "POST":
                baseline_resp = http_utils.post(form.action_url, data=baseline_data)
            else:
                baseline_resp = http_utils.get(form.action_url, params=baseline_data)
            baseline_text = baseline_resp.text
        except Exception:
            baseline_text = ""

        for payload, description in _ERROR_PAYLOADS:
            data = self._inject_form(form, field_name, payload)
            try:
                if form.method == "POST":
                    resp = http_utils.post(form.action_url, data=data)
                else:
                    resp = http_utils.get(form.action_url, params=data)
            except Exception:
                continue

            error_found = self._detect_nosql_error(resp.text)
            if error_found:
                # Skip if the same signature already appears in the baseline
                if baseline_text and error_found.lower() in baseline_text.lower():
                    continue
                self._log_finding(Finding(
                    vuln_type=VulnType.NOSQL_INJECTION,
                    severity=Severity.CRITICAL,
                    url=form.action_url,
                    parameter=field_name,
                    method="POST",
                    payload=payload,
                    evidence=(
                        f"NoSQL error triggered ({description}): "
                        f"'{error_found}' found in response. "
                        f"This indicates the application passes user input directly "
                        f"to a NoSQL database query without sanitisation."
                    ),
                    remediation=_REMEDIATION,
                    extra={"error_signature": error_found, "technique": "error-based"},
                ))
                return  # One finding per field

    def _test_form_boolean(self, form: CrawledForm, field_name: str, page_url: str) -> None:
        """Boolean-based NoSQL injection via form fields."""
        self._count_test()
        for true_payload, false_payload, description in _BOOLEAN_PAYLOADS:
            true_data = self._inject_form(form, field_name, true_payload)
            false_data = self._inject_form(form, field_name, false_payload)

            try:
                true_resp = http_utils.post(form.action_url, data=true_data)
                false_resp = http_utils.post(form.action_url, data=false_data)
            except Exception:
                continue

            if self._boolean_diff(true_resp, false_resp):
                self._log_finding(Finding(
                    vuln_type=VulnType.NOSQL_INJECTION,
                    severity=Severity.CRITICAL,
                    url=form.action_url,
                    parameter=field_name,
                    method="POST",
                    payload=f"TRUE: {true_payload} | FALSE: {false_payload}",
                    evidence=(
                        f"Boolean-based NoSQL injection ({description}): "
                        f"true condition returned {len(true_resp.content)} bytes (HTTP {true_resp.status_code}), "
                        f"false condition returned {len(false_resp.content)} bytes (HTTP {false_resp.status_code}). "
                        f"The response difference confirms the NoSQL query is controllable."
                    ),
                    remediation=_REMEDIATION,
                    extra={"technique": "boolean-based"},
                ))
                return

    def _test_get_error(self, url: str, param_name: str) -> None:
        """Inject NoSQL payloads into GET parameters."""
        self._count_test()

        # Fetch baseline to avoid flagging errors already present in normal responses
        try:
            baseline_url = self._inject_get_param(url, param_name, "baseline_nosql_test")
            baseline_resp = http_utils.get(baseline_url)
            baseline_text = baseline_resp.text
        except Exception:
            baseline_text = ""

        for payload, description in _ERROR_PAYLOADS:
            test_url = self._inject_get_param(url, param_name, payload)
            try:
                resp = http_utils.get(test_url)
            except Exception:
                continue

            error_found = self._detect_nosql_error(resp.text)
            if error_found:
                # Skip if the same signature already appears in the baseline
                if baseline_text and error_found.lower() in baseline_text.lower():
                    continue
                self._log_finding(Finding(
                    vuln_type=VulnType.NOSQL_INJECTION,
                    severity=Severity.CRITICAL,
                    url=url,
                    parameter=param_name,
                    method="GET",
                    payload=payload,
                    evidence=(
                        f"NoSQL error triggered ({description}): "
                        f"'{error_found}' found in response."
                    ),
                    remediation=_REMEDIATION,
                    extra={"error_signature": error_found, "technique": "error-based"},
                ))
                return

    def _test_get_boolean(self, url: str, param_name: str) -> None:
        """Boolean-based NoSQL injection via GET parameters."""
        self._count_test()
        for true_suffix, false_suffix, description in _GET_PAYLOADS:
            # Construct URLs with bracket notation: param[$ne]=1
            true_url = url
            false_url = url
            sep = "&" if "?" in url else "?"
            true_url = f"{url}{sep}{param_name}{true_suffix}"
            false_url = f"{url}{sep}{param_name}{false_suffix}"

            try:
                true_resp = http_utils.get(true_url)
                false_resp = http_utils.get(false_url)
            except Exception:
                continue

            if self._boolean_diff(true_resp, false_resp):
                self._log_finding(Finding(
                    vuln_type=VulnType.NOSQL_INJECTION,
                    severity=Severity.CRITICAL,
                    url=url,
                    parameter=param_name,
                    method="GET",
                    payload=f"TRUE: {param_name}{true_suffix} | FALSE: {param_name}{false_suffix}",
                    evidence=(
                        f"Boolean-based NoSQL injection ({description}): "
                        f"true={len(true_resp.content)}B, false={len(false_resp.content)}B."
                    ),
                    remediation=_REMEDIATION,
                    extra={"technique": "boolean-based"},
                ))
                return

    def _detect_nosql_error(self, body: str) -> str | None:
        """Check response body for NoSQL error signatures. Returns matched signature or None."""
        body_lower = body.lower()
        for sig in _NOSQL_ERROR_SIGNATURES:
            if sig.lower() in body_lower:
                return sig
        return None

    def _boolean_diff(self, true_resp, false_resp) -> bool:
        """Check if two responses are meaningfully different (boolean-based detection)."""
        if true_resp.status_code != false_resp.status_code:
            return True
        diff = abs(len(true_resp.content) - len(false_resp.content))
        return diff >= self._BOOLEAN_DIFF_THRESHOLD and true_resp.text != false_resp.text
