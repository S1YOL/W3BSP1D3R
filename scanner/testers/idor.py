from __future__ import annotations
"""
scanner/testers/idor.py
------------------------
Insecure Direct Object Reference (IDOR) detection.

Security concept:
  IDOR occurs when an application exposes internal object references (IDs,
  filenames, database keys) in URLs or form parameters without proper
  authorisation checks. An attacker can manipulate these references to
  access resources belonging to other users.

Detection strategy:
  1. Identify numeric parameters in GET URLs and form fields (likely object IDs)
  2. Increment/decrement the ID and compare responses
  3. If the response changes meaningfully (not a 403/404), flag as potential IDOR
  4. Also checks for UUID and sequential patterns in URL paths

This is a heuristic detector — it flags *potential* IDOR for manual verification,
since confirming true IDOR requires knowledge of authorisation boundaries.
"""

import logging
import re
from urllib.parse import urlparse, parse_qs

from scanner.crawler import CrawledPage, CrawledForm
from scanner.reporting.models import Finding, Severity, VulnType
from scanner.testers.base import BaseTester
from scanner.utils import http as http_utils

logger = logging.getLogger(__name__)


class IDORTester(BaseTester):
    """Detects potential Insecure Direct Object Reference vulnerabilities."""

    # Parameter names that commonly hold object IDs
    _ID_PARAM_PATTERNS = re.compile(
        r"(^id$|_id$|Id$|ID$|^uid$|^user_?id$|^account_?id$|^doc_?id$|"
        r"^file_?id$|^order_?id$|^item_?id$|^product_?id$|^record$|^num$|"
        r"^no$|^index$|^ref$|^key$)",
        re.IGNORECASE,
    )

    # URL path segments that look like numeric IDs
    _PATH_ID_PATTERN = re.compile(r"/(\d{1,10})(?:/|$|\?)")

    # Responses that indicate access denied (not IDOR)
    _DENIED_CODES = {401, 403}

    # Minimum response body difference (bytes) to consider meaningful
    _MIN_DIFF_BYTES = 50

    def __init__(self) -> None:
        super().__init__(name="IDOR Detector")

    def run(self, pages: list[CrawledPage]) -> list[Finding]:
        self.findings.clear()
        self._params_tested = 0

        for page in pages:
            # Test GET parameters that look like IDs
            for param_name, values in page.get_params.items():
                if not values or not self._is_id_param(param_name, values):
                    continue
                self._test_get_param(page.url, param_name, values[0])

            # Test form fields that look like IDs
            for form in page.forms:
                for field in form.fields:
                    if field.field_type == "hidden" and self._is_id_param(field.name, [field.value]):
                        self._test_form_field(form, field.name, field.value)

            # Test numeric path segments
            self._test_path_ids(page.url)

        return self.findings

    def _is_id_param(self, name: str, values: list[str]) -> bool:
        """Check if a parameter name and value look like an object ID."""
        if self._ID_PARAM_PATTERNS.search(name):
            return True
        # Also flag if the value is purely numeric (likely a DB key)
        if values and values[0].isdigit() and 1 <= len(values[0]) <= 10:
            return True
        return False

    def _test_get_param(self, url: str, param: str, original_value: str) -> None:
        """Increment/decrement a numeric GET parameter and compare responses."""
        if not original_value.isdigit():
            return

        self._count_test()
        original_id = int(original_value)

        # Get the baseline response
        try:
            baseline = http_utils.get(url)
        except Exception:
            return

        if baseline.status_code in self._DENIED_CODES or baseline.status_code == 404:
            return

        # Try adjacent IDs
        test_ids = [original_id + 1, original_id - 1]
        if original_id > 10:
            test_ids.append(1)  # Also try the first record

        for test_id in test_ids:
            if test_id < 0:
                continue

            test_url = self._inject_get_param(url, param, str(test_id))
            try:
                resp = http_utils.get(test_url)
            except Exception:
                continue

            if self._is_potential_idor(baseline, resp):
                finding = Finding(
                    vuln_type=VulnType.IDOR,
                    severity=Severity.HIGH,
                    url=url,
                    parameter=param,
                    method="GET",
                    payload=f"{param}={test_id} (original: {original_value})",
                    evidence=(
                        f"Changing {param} from {original_value} to {test_id} "
                        f"returned HTTP {resp.status_code} with {len(resp.content)} bytes "
                        f"(baseline: {len(baseline.content)} bytes). "
                        f"Different content was served without authorisation failure, "
                        f"suggesting missing access control."
                    ),
                    remediation=(
                        "Implement server-side authorisation checks for every object access. "
                        "Verify that the authenticated user owns or has permission to access "
                        "the requested resource. Use indirect references (e.g. mapping tables) "
                        "instead of exposing internal database IDs directly. "
                        "See OWASP: https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/"
                    ),
                )
                self._log_finding(finding)
                break  # One finding per parameter is enough

    def _test_form_field(self, form: CrawledForm, field_name: str, original_value: str) -> None:
        """Test a hidden form field that looks like an object ID."""
        if not original_value.isdigit():
            return

        self._count_test()
        original_id = int(original_value)

        # Get baseline
        baseline_data = self._inject_form(form, field_name, original_value)
        try:
            baseline = http_utils.post(form.action_url, data=baseline_data)
        except Exception:
            return

        if baseline.status_code in self._DENIED_CODES:
            return

        test_id = original_id + 1
        test_data = self._inject_form(form, field_name, str(test_id))
        try:
            resp = http_utils.post(form.action_url, data=test_data)
        except Exception:
            return

        if self._is_potential_idor(baseline, resp):
            finding = Finding(
                vuln_type=VulnType.IDOR,
                severity=Severity.HIGH,
                url=form.action_url,
                parameter=field_name,
                method="POST",
                payload=f"{field_name}={test_id} (original: {original_value})",
                evidence=(
                    f"Modifying hidden field '{field_name}' from {original_value} to {test_id} "
                    f"returned different content (HTTP {resp.status_code}, {len(resp.content)} bytes) "
                    f"without authorisation failure."
                ),
                remediation=(
                    "Implement server-side authorisation checks for every object access. "
                    "Never rely on hidden form fields for access control — they are trivially modifiable. "
                    "See OWASP: https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/"
                ),
            )
            self._log_finding(finding)

    def _test_path_ids(self, url: str) -> None:
        """Check for numeric IDs in URL path segments (e.g. /users/123/profile)."""
        path = urlparse(url).path
        matches = self._PATH_ID_PATTERN.findall(path)

        for match in matches:
            original_id = int(match)
            test_id = original_id + 1

            self._count_test()

            # Get baseline
            try:
                baseline = http_utils.get(url)
            except Exception:
                continue

            if baseline.status_code in self._DENIED_CODES or baseline.status_code == 404:
                continue

            # Replace the ID in the path
            test_url = url.replace(f"/{match}/", f"/{test_id}/")
            test_url = test_url.replace(f"/{match}?", f"/{test_id}?")
            if test_url.endswith(f"/{match}"):
                test_url = test_url[:-len(f"/{match}")] + f"/{test_id}"

            if test_url == url:
                continue

            try:
                resp = http_utils.get(test_url)
            except Exception:
                continue

            if self._is_potential_idor(baseline, resp):
                finding = Finding(
                    vuln_type=VulnType.IDOR,
                    severity=Severity.HIGH,
                    url=url,
                    parameter=f"path_id={match}",
                    method="GET",
                    payload=f"Changed path ID from {match} to {test_id}: {test_url}",
                    evidence=(
                        f"Incrementing numeric path segment from {match} to {test_id} "
                        f"returned HTTP {resp.status_code} with different content "
                        f"({len(resp.content)} bytes vs {len(baseline.content)} bytes). "
                        f"No authorisation failure — possible IDOR."
                    ),
                    remediation=(
                        "Implement server-side authorisation checks on all resource endpoints. "
                        "Use UUIDs or opaque tokens instead of sequential integer IDs. "
                        "See OWASP: https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/"
                    ),
                )
                self._log_finding(finding)
                break

    def _is_potential_idor(self, baseline, response) -> bool:
        """
        Determine if the response indicates a potential IDOR.
        True if: different content was returned, and no access-denied status.
        """
        # Access denied = proper authorisation in place
        if response.status_code in self._DENIED_CODES:
            return False

        # 404 = resource doesn't exist, not IDOR
        if response.status_code == 404:
            return False

        # Must get a successful response
        if response.status_code != 200:
            return False

        # Content must be meaningfully different from baseline
        diff = abs(len(response.content) - len(baseline.content))
        if diff < self._MIN_DIFF_BYTES:
            return False

        # Content should actually be different (not just length)
        if response.text == baseline.text:
            return False

        return True
