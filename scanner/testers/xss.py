from __future__ import annotations
"""
scanner/testers/xss.py
-----------------------
Cross-Site Scripting (XSS) vulnerability tester.

Security concept (OWASP A03:2021 – Injection):
  XSS occurs when an application takes untrusted data and sends it to a web
  browser without proper validation or encoding. An attacker can execute
  arbitrary JavaScript in the victim's browser — stealing session cookies,
  redirecting to phishing pages, or silently performing actions on behalf of
  the victim (account takeover).

Two attack vectors tested:

1. Reflected XSS
   ──────────────
   The injected payload is immediately echoed back in the HTTP response.
   Detection: inject a unique JavaScript payload, then check if it appears
   unescaped in the response body. We use a distinctive marker string so
   we can confirm the payload survived encoding/filtering.

   Example payload: <script>alert('XSS-RFL-test-1')</script>
   Evidence: the literal string appears in the response HTML.

2. Stored (Persistent) XSS
   ─────────────────────────
   The payload is stored in the backend (database, file, etc.) and rendered
   to ALL users who visit the affected page later — much higher severity.

   Detection:
     Step 1 — Submit the payload via a form (POST).
     Step 2 — Fetch the same page (or a "view" page) via GET.
     Step 3 — Check if the payload survived storage and appears in the GET
               response.
   We use marker strings unique per test so we can distinguish stored from
   reflected output.

Severity:
  Reflected XSS → High  (requires social engineering / phishing link)
  Stored XSS    → High/Critical (affects all visitors automatically)

Remediation:
  Output-encode all user-supplied data (HTML entity encoding).
  Implement Content Security Policy (CSP) headers.
  Use a framework that auto-escapes template variables.
  Never use innerHTML / document.write with unsanitised data.
"""

import logging
import re
import secrets
from typing import NamedTuple

from scanner.crawler import CrawledForm, CrawledPage
from scanner.reporting.models import Finding, Severity, VulnType
from scanner.testers.base import BaseTester
from scanner.utils import http as http_utils
from scanner.utils.display import print_status

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# XSS payload catalogue
# ---------------------------------------------------------------------------

class XSSPayload(NamedTuple):
    template:    str   # May contain {marker} placeholder
    description: str
    context:     str   # "script_tag", "attribute", "event_handler", "js_string"


# Reflected XSS payloads — each uses a unique marker token for unambiguous detection
REFLECTED_PAYLOADS: list[XSSPayload] = [
    XSSPayload(
        "<script>alert('{marker}')</script>",
        "Classic script tag injection",
        "script_tag",
    ),
    XSSPayload(
        "<img src=x onerror=alert('{marker}')>",
        "Image onerror event handler",
        "event_handler",
    ),
    XSSPayload(
        '"><script>alert("{marker}")</script>',
        "Attribute break-out into script tag",
        "attribute",
    ),
    XSSPayload(
        "'><svg onload=alert('{marker}')>",
        "SVG onload event handler",
        "event_handler",
    ),
    XSSPayload(
        "<body onload=alert('{marker}')>",
        "Body onload handler",
        "event_handler",
    ),
    XSSPayload(
        "javascript:alert('{marker}')",
        "JavaScript URL protocol (href/src injection)",
        "js_string",
    ),
    XSSPayload(
        "<details open ontoggle=alert('{marker}')>",
        "HTML5 details ontoggle (bypasses some filters)",
        "event_handler",
    ),
    XSSPayload(
        '"><input autofocus onfocus=alert("{marker}")>',
        "Input autofocus onfocus (no user interaction needed)",
        "event_handler",
    ),
]

# Stored XSS payloads — same list but the marker is stored then retrieved
STORED_PAYLOADS: list[XSSPayload] = REFLECTED_PAYLOADS  # reuse for now

_REFLECTED_REMEDIATION = (
    "Encode all user-supplied output using HTML entity encoding before rendering "
    "(e.g. use htmlspecialchars() in PHP, Jinja2 auto-escaping in Python, React JSX). "
    "Implement a strict Content-Security-Policy (CSP) header. "
    "Validate input server-side — reject or sanitise unexpected characters. "
    "Ref: OWASP XSS Prevention Cheat Sheet."
)

_STORED_REMEDIATION = (
    "Stored XSS is higher severity than reflected — ALL users are at risk. "
    "Store data raw but encode on output (never trust stored data). "
    "Implement CSP with 'script-src' restricted to known origins. "
    "Use a sanitisation library (e.g. DOMPurify) for rich-text fields. "
    "Ref: OWASP XSS Prevention Cheat Sheet, OWASP DOM-based XSS Guide."
)


# ---------------------------------------------------------------------------
# XSS Tester
# ---------------------------------------------------------------------------

class XSSTester(BaseTester):
    """
    Tests for reflected and stored/persistent XSS vulnerabilities.
    """

    def __init__(self) -> None:
        super().__init__(name="XSS Tester")

    # ------------------------------------------------------------------
    # Entry point
    # ------------------------------------------------------------------

    def run(self, pages: list[CrawledPage]) -> list[Finding]:
        """
        Test every form field and GET parameter on every crawled page.
        """
        self.findings.clear()
        self._params_tested = 0

        for page in pages:
            for form in page.forms:
                for field in form.testable_fields:
                    self._test_form_field(form, field.name)

            for param in page.get_params:
                self._test_get_param(page.url, param)

        return self.findings

    # ------------------------------------------------------------------
    # Form testing
    # ------------------------------------------------------------------

    def _test_form_field(self, form: CrawledForm, field_name: str) -> None:
        """
        Run both reflected and stored XSS tests on a single form field.

        We run reflected first (fast), then stored (requires two requests).
        Once a finding is confirmed we still continue to stored — a field
        can be vulnerable to both independently.
        """
        self._count_test()
        print_status(f"XSS  → {form.action_url} [{form.method}] param={field_name}")

        self._reflected_form(form, field_name)
        self._stored_form(form, field_name)

    def _reflected_form(self, form: CrawledForm, field_name: str) -> None:
        """
        Test for reflected XSS via a form field.

        Algorithm:
          For each payload:
            1. Generate a unique marker (prevents false positives from cached responses)
            2. Submit the form with the payload (marker embedded)
            3. Check if the marker appears in the response body
               — if yes, the payload was reflected without encoding
        """
        for xss_payload in REFLECTED_PAYLOADS:
            marker  = self._make_marker()
            payload = xss_payload.template.replace("{marker}", marker)

            data = self._inject_form(form, field_name, payload)
            try:
                if form.method == "POST":
                    resp = http_utils.post(form.action_url, data=data)
                else:
                    resp = http_utils.get(form.action_url, params=data)
            except Exception:
                continue

            if self._is_reflected(marker, resp.text, payload):
                snippet = self._extract_error_snippet(resp.text, marker, window=200)
                self._log_finding(Finding(
                    vuln_type=VulnType.XSS_REFLECTED,
                    severity=Severity.HIGH,
                    url=form.action_url,
                    parameter=field_name,
                    method=form.method,
                    payload=payload,
                    evidence=(
                        f"Marker '{marker}' reflected unencoded in response: "
                        f"…{snippet}…"
                    ),
                    remediation=_REFLECTED_REMEDIATION,
                    extra={
                        "payload_context": xss_payload.context,
                        "marker": marker,
                    },
                ))
                return  # One confirmed finding per field is enough

    def _stored_form(self, form: CrawledForm, field_name: str) -> None:
        """
        Test for stored (persistent) XSS via a form field.

        Algorithm:
          1. Generate a unique marker.
          2. POST the payload to the form action (store it).
          3. GET the form's page URL — if the payload is stored, it will appear
             in the freshly fetched page HTML.

        Note: this is a simplified heuristic. Production scanners also crawl
        "view" or "list" pages after submission. We check the originating
        page_url which is often a submission confirmation or listing page.
        """
        for xss_payload in STORED_PAYLOADS:
            marker  = self._make_marker()
            payload = xss_payload.template.replace("{marker}", marker)

            # Step 1 — POST (store the payload)
            data = self._inject_form(form, field_name, payload)
            try:
                if form.method == "POST":
                    http_utils.post(form.action_url, data=data)
                else:
                    continue  # Stored XSS via GET forms is unusual — skip
            except Exception:
                continue

            # Step 2 — GET the page to see if payload persisted
            fetch_url = form.page_url  # The page the form lived on
            try:
                resp = http_utils.get(fetch_url)
            except Exception:
                continue

            if self._is_reflected(marker, resp.text, payload):
                snippet = self._extract_error_snippet(resp.text, marker, window=200)
                self._log_finding(Finding(
                    vuln_type=VulnType.XSS_STORED,
                    severity=Severity.HIGH,
                    url=form.action_url,
                    parameter=field_name,
                    method=form.method,
                    payload=payload,
                    evidence=(
                        f"Marker '{marker}' found in subsequent GET of "
                        f"{fetch_url} — payload persisted in storage: …{snippet}…"
                    ),
                    remediation=_STORED_REMEDIATION,
                    extra={
                        "stored_on": fetch_url,
                        "payload_context": xss_payload.context,
                        "marker": marker,
                    },
                ))
                return

    # ------------------------------------------------------------------
    # GET parameter testing
    # ------------------------------------------------------------------

    def _test_get_param(self, url: str, param_name: str) -> None:
        """Test reflected XSS via a GET query parameter."""
        self._count_test()
        print_status(f"XSS  → {url} [GET] param={param_name}")
        self._reflected_get(url, param_name)

    def _reflected_get(self, url: str, param_name: str) -> None:
        for xss_payload in REFLECTED_PAYLOADS:
            marker  = self._make_marker()
            payload = xss_payload.template.replace("{marker}", marker)

            injected_url = self._inject_get_param(url, param_name, payload)
            try:
                resp = http_utils.get(injected_url)
            except Exception:
                continue

            if self._is_reflected(marker, resp.text, payload):
                snippet = self._extract_error_snippet(resp.text, marker, window=200)
                self._log_finding(Finding(
                    vuln_type=VulnType.XSS_REFLECTED,
                    severity=Severity.HIGH,
                    url=injected_url,
                    parameter=param_name,
                    method="GET",
                    payload=payload,
                    evidence=f"Marker '{marker}' reflected unencoded: …{snippet}…",
                    remediation=_REFLECTED_REMEDIATION,
                    extra={
                        "payload_context": xss_payload.context,
                        "marker": marker,
                    },
                ))
                return

    # ------------------------------------------------------------------
    # Detection helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _make_marker() -> str:
        """
        Generate a short, unique, alphanumeric marker that:
          - Is distinctive enough to avoid collisions with page content
          - Contains no special characters that might be independently encoded
          - Is easy to search for in a response body

        We use secrets.token_hex(4) for 8 hex chars of randomness — unique
        enough for our purposes without being so long it triggers WAF rules.
        """
        return f"XSSTEST{secrets.token_hex(4).upper()}"

    @staticmethod
    def _is_reflected(marker: str, response_text: str, payload: str = "") -> bool:
        """
        Verify that a XSS payload landed in the response **unencoded**.

        Two-stage check:
          1. The alphanumeric marker must be present (fast reject).
          2. At least one *structural* element of the payload (tag, attribute,
             event handler, or javascript: protocol) must survive HTML-encoding
             in the neighbourhood of the marker.

        This eliminates the dominant class of XSS false positives — apps that
        reflect user input but apply proper HTML entity encoding.
        """
        text_lower = response_text.lower()
        marker_lower = marker.lower()

        if marker_lower not in text_lower:
            return False

        # If no payload was supplied, fall back to marker-only (legacy path)
        if not payload:
            return True

        # Build structural patterns that must contain the marker itself for the
        # XSS to be exploitable. Every pattern is anchored to {m} so that an
        # unrelated event-handler tag elsewhere on the page (which merely shares
        # the page with a harmlessly-reflected marker) cannot trigger a match.
        m = re.escape(marker_lower)
        structural_patterns = [
            # Marker sits inside a live <script> block
            rf"<script[^>]*>[^<]*{m}",
            # Marker sits inside an opening tag that also carries an event handler
            # e.g. <img src=x onerror=alert('MARKER')>  or  <svg onload=...MARKER...>
            rf"<[a-z][a-z0-9]*\b[^>]*\son\w+\s*=[^>]*{m}[^<]*>",
            # Marker sits inside a javascript: URI
            rf"javascript\s*:[^<>]{{0,80}}?{m}",
        ]

        for pattern in structural_patterns:
            if re.search(pattern, text_lower, re.IGNORECASE | re.DOTALL):
                return True

        return False
