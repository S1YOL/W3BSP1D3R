from __future__ import annotations
"""
scanner/testers/clickjacking.py
---------------------------------
Clickjacking / UI redressing vulnerability tester.

Checks whether the target can be embedded in an iframe by a malicious site,
which would allow an attacker to trick users into clicking on hidden elements.

Tests:
  - X-Frame-Options header (DENY, SAMEORIGIN, ALLOW-FROM)
  - Content-Security-Policy frame-ancestors directive
  - Missing framing protection entirely
  - Inconsistent framing policies across pages
"""

import logging
import re

from scanner.testers.base import BaseTester
from scanner.crawler import CrawledPage
from scanner.reporting.models import Finding, Severity
from scanner.utils import http as http_utils

logger = logging.getLogger(__name__)


class ClickjackingTester(BaseTester):
    """Test for clickjacking / UI redressing vulnerabilities."""

    def __init__(self) -> None:
        super().__init__(name="Clickjacking Protection")

    def run(self, pages: list[CrawledPage]) -> list[Finding]:
        if not pages:
            return self.findings

        pages = self._filter_pages_by_scope(pages)
        tested_origins = set()

        for page in pages[:10]:
            self._count_test()
            try:
                resp = http_utils.get(page.url)
            except Exception:
                continue

            xfo = resp.headers.get("X-Frame-Options", "").strip().upper()
            csp = resp.headers.get("Content-Security-Policy", "")

            has_xfo = bool(xfo)
            has_frame_ancestors = "frame-ancestors" in csp.lower()

            # Extract frame-ancestors value
            fa_value = ""
            if has_frame_ancestors:
                match = re.search(r"frame-ancestors\s+([^;]+)", csp, re.IGNORECASE)
                if match:
                    fa_value = match.group(1).strip()

            # Check 1: No framing protection at all
            if not has_xfo and not has_frame_ancestors:
                from urllib.parse import urlparse
                origin = urlparse(page.url).netloc
                if origin not in tested_origins:
                    tested_origins.add(origin)
                    self._log_finding(Finding(
                        vuln_type="Clickjacking — No Framing Protection",
                        severity=Severity.MEDIUM,
                        url=page.url,
                        parameter="X-Frame-Options / CSP frame-ancestors",
                        method="GET",
                        payload="Check response headers",
                        evidence=(
                            "Neither X-Frame-Options nor CSP frame-ancestors "
                            "header is set. The page can be embedded in an "
                            "iframe on any malicious site."
                        ),
                        remediation=(
                            "Add X-Frame-Options: DENY (or SAMEORIGIN if iframes "
                            "are needed within your own site). Better yet, use CSP: "
                            "Content-Security-Policy: frame-ancestors 'self'. "
                            "This prevents your pages from being embedded in "
                            "attacker-controlled iframes."
                        ),
                    ))

            # Check 2: Weak X-Frame-Options
            elif has_xfo and xfo == "ALLOW-FROM":
                self._log_finding(Finding(
                    vuln_type="Clickjacking — Weak X-Frame-Options",
                    severity=Severity.LOW,
                    url=page.url,
                    parameter="X-Frame-Options",
                    method="GET",
                    payload="Check X-Frame-Options header",
                    evidence=(
                        f"X-Frame-Options: {xfo}. ALLOW-FROM is deprecated "
                        f"and not supported by modern browsers (Chrome, Firefox). "
                        f"Use CSP frame-ancestors instead."
                    ),
                    remediation=(
                        "Replace X-Frame-Options: ALLOW-FROM with "
                        "Content-Security-Policy: frame-ancestors 'self' https://trusted-site.com. "
                        "ALLOW-FROM is not supported in Chrome or Firefox."
                    ),
                ))

            # Check 3: Wildcard frame-ancestors
            elif has_frame_ancestors and ("*" in fa_value or "'none'" not in fa_value.lower()):
                if "*" in fa_value:
                    self._log_finding(Finding(
                        vuln_type="Clickjacking — Wildcard frame-ancestors",
                        severity=Severity.MEDIUM,
                        url=page.url,
                        parameter="CSP frame-ancestors",
                        method="GET",
                        payload="Check Content-Security-Policy header",
                        evidence=(
                            f"CSP frame-ancestors contains wildcard (*): {fa_value}. "
                            f"Any site can embed this page in an iframe."
                        ),
                        remediation=(
                            "Replace wildcard with specific trusted origins: "
                            "frame-ancestors 'self' https://trusted-partner.com"
                        ),
                    ))

        return self.findings
