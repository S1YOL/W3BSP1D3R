from __future__ import annotations
"""
scanner/testers/csrf.py
------------------------
Cross-Site Request Forgery (CSRF) vulnerability tester.

Security concept (OWASP A01:2021 – Broken Access Control / CSRF):
  CSRF tricks an authenticated user's browser into making unwanted requests
  to a web application. Because the browser automatically sends session
  cookies, the server cannot distinguish a legitimate request from a forged
  one — unless the application implements anti-CSRF tokens.

  Classic attack scenario:
    1. Victim is logged into bank.com.
    2. Attacker sends victim a link to evil.com/csrf-attack.html.
    3. That page silently submits a form to bank.com/transfer?to=attacker.
    4. bank.com sees a valid session cookie and processes the transfer.

Detection approach:
  We classify forms into three tiers:

  VULNERABLE — The form has no CSRF token whatsoever. Any state-changing
    POST request can be forged by any origin. Severity: High.

  WEAK — A token exists but:
    (a) It appears static across requests (we compare two consecutive fetches),
    (b) It is shorter than 16 characters (too short to be cryptographically strong),
    (c) It appears in the URL / GET params instead of a hidden POST field.
    Severity: Medium.

  OK — A hidden field with a strong, unique, per-session token exists.

  We also flag forms that:
    - Accept GET method for state-changing operations (unusual but dangerous)
    - Have a Referer-only CSRF defence (trivially bypassed)

  Note: CSRF is less severe in applications that use SameSite=Strict cookies
  (modern browsers auto-defend) or CORS restrictions, but we flag the form
  itself since we can't confirm cookie attributes without a full response audit.

Severity: High (direct exploitation requires a phishing scenario but impact
can include account takeover, data deletion, or financial actions).

Remediation:
  - Implement synchroniser token pattern (CSRF token per session per form)
  - Use SameSite=Strict or SameSite=Lax cookie attribute
  - Verify Origin / Referer headers server-side (defence-in-depth)
  - Consider Double Submit Cookie pattern for stateless APIs
  - Ref: OWASP CSRF Prevention Cheat Sheet
"""

import logging
import re

from bs4 import BeautifulSoup

from scanner.crawler import CrawledForm, CrawledPage
from scanner.reporting.models import Finding, Severity, VulnType
from scanner.testers.base import BaseTester
from scanner.utils import http as http_utils
from scanner.utils.display import print_status

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

# Minimum length for a token to be considered cryptographically strong
MIN_TOKEN_LENGTH = 16

# Hidden field names that commonly carry CSRF tokens
_CSRF_TOKEN_FIELD_NAMES: set[str] = {
    "csrf_token", "csrf", "_token", "token", "authenticity_token",
    "user_token", "_csrf_token", "csrfmiddlewaretoken", "anticsrf",
    "requestverificationtoken", "__requestverificationtoken", "nonce",
    "_wpnonce", "formtoken", "form_key",
}

# Methods that change server state — these MUST have CSRF protection
_STATE_CHANGING_METHODS = {"POST", "PUT", "PATCH", "DELETE"}

# Action URL fragments that strongly suggest state-changing operations
_SENSITIVE_ACTION_KEYWORDS = {
    "delete", "remove", "update", "edit", "change", "reset",
    "transfer", "pay", "submit", "save", "create", "add",
    "register", "logout", "password", "admin", "settings",
    "profile", "account",
}

_REMEDIATION = (
    "Add a cryptographically random CSRF token (≥ 128-bit entropy) to every "
    "state-changing form as a hidden field. Validate the token server-side on "
    "every non-GET request. Additionally, set SameSite=Strict on session cookies "
    "and verify the Origin/Referer header as defence-in-depth. "
    "Ref: OWASP CSRF Prevention Cheat Sheet."
)

_WEAK_TOKEN_REMEDIATION = (
    "The CSRF token present appears weak (too short, static, or in a GET param). "
    "Replace with a cryptographically random per-session token (min 128-bit / 16 bytes). "
    "Regenerate the token on each login and store it server-side for validation. "
    "Ref: OWASP CSRF Prevention Cheat Sheet."
)


# ---------------------------------------------------------------------------
# CSRF Tester
# ---------------------------------------------------------------------------

class CSRFTester(BaseTester):
    """
    Analyses HTML forms for missing or weak CSRF protections.

    Unlike SQLi/XSS testers, we do NOT actively forge requests — we perform
    passive analysis of form structure and token quality. Active CSRF testing
    would require a separate browser origin simulation, which is out of scope
    for this educational tool.
    """

    def __init__(self) -> None:
        super().__init__(name="CSRF Tester")

    # ------------------------------------------------------------------
    # Entry point
    # ------------------------------------------------------------------

    def run(self, pages: list[CrawledPage]) -> list[Finding]:
        """
        Analyse all forms found during crawling for CSRF weaknesses.
        """
        self.findings.clear()
        self._params_tested = 0

        # Deduplicate forms by action_url + method — same form on multiple
        # pages (e.g. in a nav bar) should only be tested once.
        seen: set[str] = set()

        for page in pages:
            for form in page.forms:
                dedup_key = f"{form.method}:{form.action_url}"
                if dedup_key in seen:
                    continue
                seen.add(dedup_key)

                self._analyse_form(form)

        return self.findings

    # ------------------------------------------------------------------
    # Form analysis
    # ------------------------------------------------------------------

    def _analyse_form(self, form: CrawledForm) -> None:
        """
        Inspect a single form for CSRF weaknesses.

        Decision tree:
          1. Is the method state-changing (POST)?           → must have a token
          2. Is the action URL sensitive (contains sensitive keywords)?
          3. Does a token field exist?
             - No  → VULNERABLE
             - Yes → check quality (length, uniqueness, location)
        """
        self._count_test()
        print_status(f"CSRF → {form.action_url} [{form.method}]")

        # GET forms can't directly be CSRF'd (GET should be idempotent),
        # but flag if the action looks state-changing
        if form.method not in _STATE_CHANGING_METHODS:
            if self._action_looks_sensitive(form.action_url):
                self._log_finding(Finding(
                    vuln_type=VulnType.CSRF,
                    severity=Severity.LOW,
                    url=form.action_url,
                    parameter="(form method)",
                    method=form.method,
                    payload="N/A — passive analysis",
                    evidence=(
                        f"Form uses {form.method} method but action URL suggests a "
                        f"state-changing operation ({form.action_url}). "
                        "GET requests should be idempotent and non-state-changing."
                    ),
                    remediation=(
                        "Change state-changing operations to use POST (or PUT/DELETE for APIs). "
                        "GET requests are bookmarkable and sent in Referer headers — "
                        "they must not modify server state."
                    ),
                ))
            return  # No further CSRF analysis for GET forms

        # --- POST form analysis ---
        token_field = self._find_csrf_token_field(form)

        if token_field is None:
            # No token at all — clearly vulnerable
            self._log_finding(Finding(
                vuln_type=VulnType.CSRF,
                severity=Severity.HIGH,
                url=form.action_url,
                parameter="(no csrf token)",
                method=form.method,
                payload="N/A — passive analysis",
                evidence=(
                    f"POST form at {form.action_url} has no CSRF token field. "
                    f"Form fields: {[f.name for f in form.fields]}. "
                    "An attacker from any origin can forge this request."
                ),
                remediation=_REMEDIATION,
                extra={"form_fields": [f.name for f in form.fields]},
            ))
            return

        # --- Token found — assess quality ---
        token_value = token_field.value

        weaknesses = []

        if len(token_value) < MIN_TOKEN_LENGTH:
            weaknesses.append(
                f"Token is too short ({len(token_value)} chars < {MIN_TOKEN_LENGTH} required)"
            )

        if self._token_looks_static(token_value):
            weaknesses.append(
                "Token value appears static or predictable (all same char, sequential, or very short)"
            )

        if self._is_token_in_get_params(form):
            weaknesses.append(
                "Token appears in URL query parameters (GET param) — visible in logs and Referer headers"
            )

        if weaknesses:
            self._log_finding(Finding(
                vuln_type=VulnType.CSRF,
                severity=Severity.MEDIUM,
                url=form.action_url,
                parameter=token_field.name,
                method=form.method,
                payload=f"Observed token value: '{token_value[:32]}…'" if len(token_value) > 32 else f"Observed token value: '{token_value}'",
                evidence=(
                    f"CSRF token field '{token_field.name}' found but has weaknesses: "
                    + " | ".join(weaknesses)
                ),
                remediation=_WEAK_TOKEN_REMEDIATION,
                extra={
                    "token_field":  token_field.name,
                    "token_length": len(token_value),
                    "weaknesses":   weaknesses,
                },
            ))

        # If token looks strong, we check for static token across requests
        else:
            second_token = self._fetch_token_second_request(form, token_field.name)
            if second_token is not None and second_token == token_value and token_value:
                self._log_finding(Finding(
                    vuln_type=VulnType.CSRF,
                    severity=Severity.MEDIUM,
                    url=form.action_url,
                    parameter=token_field.name,
                    method=form.method,
                    payload=f"Static token: '{token_value[:32]}…'",
                    evidence=(
                        f"CSRF token '{token_field.name}' has the same value across two "
                        "separate requests — it is NOT per-session or per-request. "
                        "A static token provides no CSRF protection."
                    ),
                    remediation=_WEAK_TOKEN_REMEDIATION,
                    extra={
                        "token_field":     token_field.name,
                        "token_request_1": token_value,
                        "token_request_2": second_token,
                    },
                ))

    # ------------------------------------------------------------------
    # Token discovery helpers
    # ------------------------------------------------------------------

    def _find_csrf_token_field(self, form: CrawledForm):
        """
        Find the CSRF token field in a form's hidden inputs.

        Matching strategy:
          1. Name matches a known CSRF token field name (case-insensitive).
          2. Field is a hidden input (type="hidden") — CSRF tokens live here.
          3. Fallback: any hidden field with "token" or "csrf" in its name.
        """
        # First pass — exact known-names match
        for field in form.hidden_fields:
            if field.name.lower() in _CSRF_TOKEN_FIELD_NAMES:
                return field

        # Second pass — fuzzy match on "token" or "csrf" substring
        for field in form.hidden_fields:
            name_lower = field.name.lower()
            if "token" in name_lower or "csrf" in name_lower or "nonce" in name_lower:
                return field

        return None

    def _action_looks_sensitive(self, action_url: str) -> bool:
        """Return True if the action URL contains state-changing keywords."""
        url_lower = action_url.lower()
        return any(kw in url_lower for kw in _SENSITIVE_ACTION_KEYWORDS)

    def _token_looks_static(self, token: str) -> bool:
        """
        Heuristics to detect obviously weak token values:
          - All same character (e.g. "0000000000")
          - Simple sequential digits (e.g. "12345678")
          - Empty string
          - Purely numeric short values
        """
        if not token:
            return True
        if len(set(token)) <= 2:       # e.g. "0000" or "0101"
            return True
        if token.isdigit() and len(token) < 10:
            return True
        # Sequential ASCII chars
        if token in "abcdefghijklmnopqrstuvwxyz0123456789":
            return True
        return False

    def _is_token_in_get_params(self, form: CrawledForm) -> bool:
        """Return True if the action URL contains a token-like GET parameter."""
        action_lower = form.action_url.lower()
        return any(kw in action_lower for kw in ("token=", "csrf=", "nonce=", "_token="))

    def _fetch_token_second_request(
        self, form: CrawledForm, token_field_name: str
    ) -> str | None:
        """
        Fetch the form's page a second time and extract the CSRF token value.
        If it equals the first-request token, the token is static.

        Returns the token value string, or None on fetch/parse failure.
        """
        try:
            resp = http_utils.get(form.page_url)
        except Exception:
            return None

        soup  = BeautifulSoup(resp.text, "lxml")
        field = soup.find("input", {"name": token_field_name, "type": "hidden"})
        if field:
            return field.get("value", "")
        return None
