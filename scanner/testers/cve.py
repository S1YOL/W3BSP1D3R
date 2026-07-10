from __future__ import annotations
"""
scanner/testers/cve.py
-----------------------
CVE (Common Vulnerabilities & Exposures) lookup tester.

Fingerprints server software from HTTP response headers, then queries
the NIST National Vulnerability Database (NVD) API v2 for known CVEs
affecting the detected versions.

For each CVE found the finding includes:
  - CVE ID with a direct link to nvd.nist.gov/vuln/detail/<id>
  - CVSS v3 base score mapped to our severity tiers
  - Brief description
  - Affected product and version

NVD API docs : https://nvd.nist.gov/developers/vulnerabilities
Rate limits  : 5 req / 30 s without key  |  50 req / 30 s with key
               Pass --nvd-api-key to raise the limit.

OWASP ref    : A06:2021 Vulnerable and Outdated Components
"""

import re
import time
import logging
from typing import Optional

import requests

from scanner.testers.base import BaseTester
from scanner.crawler import CrawledPage
from scanner.reporting.models import Finding, Severity
from scanner.utils import http as http_utils

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Header fingerprint rules
# (header_name, version_capture_regex_or_None, display_product_name)
# If the regex is None, header presence alone signals the product.
# ---------------------------------------------------------------------------
_FINGERPRINTS: list[tuple[str, Optional[str], str]] = [
    ("Server",          r"Apache[/ ]([\d]+\.[\d.]+)",         "Apache HTTP Server"),
    ("Server",          r"nginx[/ ]([\d]+\.[\d.]+)",          "nginx"),
    ("Server",          r"Microsoft-IIS[/ ]([\d]+\.[\d.]+)",  "Microsoft IIS"),
    ("Server",          r"Tomcat[/ ]([\d]+\.[\d.]+)",         "Apache Tomcat"),
    ("Server",          r"LiteSpeed[/ ]?([\d]+\.[\d.]+)",     "LiteSpeed"),
    ("Server",          r"OpenSSL[/ ]([\d]+\.[\d.]+[a-z]?)",  "OpenSSL"),
    ("X-Powered-By",    r"PHP[/ ]([\d]+\.[\d.]+)",            "PHP"),
    ("X-Powered-By",    r"ASP\.NET",                          "ASP.NET"),
    ("X-Generator",     r"WordPress ([\d]+\.[\d.]+)",         "WordPress"),
    ("X-Drupal-Cache",  None,                                 "Drupal"),
    ("X-Joomla-Token",  None,                                 "Joomla"),
]

_NVD_API    = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_NVD_DETAIL = "https://nvd.nist.gov/vuln/detail/{cve_id}"

_REMEDIATION = (
    "Update {product} to the latest stable release to eliminate known CVEs. "
    "Monitor https://nvd.nist.gov for new advisories. "
    "Full CVE detail: {link}"
)


def _score_to_severity(score: float) -> str:
    if score >= 9.0:
        return Severity.CRITICAL
    if score >= 7.0:
        return Severity.HIGH
    if score >= 4.0:
        return Severity.MEDIUM
    return Severity.LOW


class CveTester(BaseTester):
    """
    Fingerprints server technology from HTTP response headers, then looks up
    known CVEs via the NIST NVD API v2.

    Pipeline:
      1. GET the target URL using the shared scanner session to collect headers.
      2. Apply regex rules to extract product name + version string.
      3. Query the NVD API for up to 5 CVEs per detected product.
      4. Emit one Finding per CVE, severity mapped from CVSS base score.
    """

    def __init__(self, nvd_api_key: Optional[str] = None) -> None:
        super().__init__(name="CVE Lookup")
        self._nvd_key = nvd_api_key
        # Dedicated session so NVD auth headers don't bleed into scan traffic
        self._nvd = requests.Session()
        self._nvd.headers.update({
            "User-Agent": "W3BSP1D3R/1.0 CVE-Lookup (Educational; by S1YOL)",
        })
        if nvd_api_key:
            self._nvd.headers["apiKey"] = nvd_api_key

    # ------------------------------------------------------------------
    # BaseTester contract
    # ------------------------------------------------------------------

    def run(self, pages: list[CrawledPage]) -> list[Finding]:
        self.findings.clear()
        self._params_tested = 0

        if not pages:
            return self.findings

        # Step 1 — fingerprint server software from the first page's URL
        detected = self._fingerprint(pages[0].url)
        if not detected:
            logger.debug("CVE tester: no software fingerprinted — headers not exposed")
            return self.findings

        # Step 2 — NVD lookup per product (rate-limited)
        products = list(detected.items())
        for idx, (product, version) in enumerate(products):
            self._count_test()
            for finding in self._lookup_nvd(product, version):
                self._log_finding(finding)
            # NVD free tier: 5 req / 30 s → sleep between calls except the last
            if idx < len(products) - 1:
                time.sleep(7)

        return self.findings

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _fingerprint(self, target_url: str) -> dict[str, str]:
        """
        Fetch the target URL and extract product → version from response headers.
        Returns {} if the request fails.
        """
        detected: dict[str, str] = {}
        try:
            resp = http_utils.get(target_url)
            headers = resp.headers
        except Exception as exc:
            logger.warning("CVE tester: could not fetch %s: %s", target_url, exc)
            return detected

        for header, pattern, product in _FINGERPRINTS:
            if product in detected:
                continue
            val = headers.get(header, "")
            if not val:
                continue

            if pattern:
                m = re.search(pattern, val, re.IGNORECASE)
                if not m:
                    continue
                version = m.group(1) if m.lastindex and m.lastindex >= 1 else "unknown"
                detected[product] = version
                logger.debug("Fingerprinted %s %s via %s header", product, version, header)
            else:
                # Header presence alone → product confirmed, version unknown
                detected[product] = "unknown"
                logger.debug("Fingerprinted %s (no version) via %s header", product, header)

        return detected

    def _lookup_nvd(self, product: str, version: str) -> list[Finding]:
        """
        Query the NVD API for CVEs matching `product version`.
        Returns up to 5 Findings sorted by CVSS score descending.
        """
        findings: list[Finding] = []
        keyword = f"{product} {version}" if version != "unknown" else product

        try:
            resp = self._nvd.get(
                _NVD_API,
                params={"keywordSearch": keyword, "resultsPerPage": 5},
                timeout=15,
            )
            resp.raise_for_status()
            data = resp.json()
        except requests.HTTPError as exc:
            logger.warning("NVD HTTP error for '%s': %s", keyword, exc)
            return findings
        except Exception as exc:
            logger.warning("NVD API error for '%s': %s", keyword, exc)
            return findings

        for item in data.get("vulnerabilities", []):
            cve_data = item.get("cve", {})
            cve_id   = cve_data.get("id", "UNKNOWN")

            # English description
            desc = next(
                (d["value"] for d in cve_data.get("descriptions", [])
                 if d.get("lang") == "en"),
                "No description available.",
            )

            # CVSS score — prefer v3.1, fall back to v3.0, then v2
            score = 0.0
            for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                entries = cve_data.get("metrics", {}).get(key, [])
                if entries:
                    score = float(entries[0].get("cvssData", {}).get("baseScore", 0.0))
                    break

            link = _NVD_DETAIL.format(cve_id=cve_id)

            findings.append(Finding(
                vuln_type   = f"CVE — {product}",
                severity    = _score_to_severity(score),
                url         = link,
                parameter   = "Server banner / response header",
                method      = "passive",
                payload     = f"Detected: {product} {version}",
                evidence    = f"{cve_id} (CVSS {score:.1f}): {desc[:300]}",
                remediation = _REMEDIATION.format(product=product, link=link),
            ))

        return findings
