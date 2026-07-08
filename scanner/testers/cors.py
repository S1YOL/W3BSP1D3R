from __future__ import annotations
"""
scanner/testers/cors.py
------------------------
CORS (Cross-Origin Resource Sharing) misconfiguration detection.

Security concept:
  Misconfigured CORS policies allow attacker-controlled websites to make
  authenticated cross-origin requests and read responses. This can lead
  to data theft, account takeover, and API abuse.

Detection strategy:
  1. Send requests with crafted Origin headers
  2. Check if the server reflects the attacker origin in Access-Control-Allow-Origin
  3. Check if credentials are allowed (Access-Control-Allow-Credentials: true)
  4. Test for wildcard origins, null origin, and subdomain trust

OWASP ref: A01:2021 Broken Access Control, A05:2021 Security Misconfiguration
"""

import logging
from urllib.parse import urlparse

from scanner.crawler import CrawledPage
from scanner.reporting.models import Finding, Severity, VulnType
from scanner.testers.base import BaseTester
from scanner.utils import http as http_utils

logger = logging.getLogger(__name__)

_REMEDIATION = (
    "Configure CORS with a strict allowlist of trusted origins. Never reflect "
    "arbitrary Origin headers back in Access-Control-Allow-Origin. Avoid using "
    "'*' with credentials. Do not trust 'null' origins. "
    "Ref: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/07-Testing_Cross_Origin_Resource_Sharing"
)


class CORSTester(BaseTester):
    """Detects dangerous CORS misconfigurations."""

    def __init__(self) -> None:
        super().__init__(name="CORS Tester")

    def run(self, pages: list[CrawledPage]) -> list[Finding]:
        self.findings.clear()
        self._params_tested = 0

        # Deduplicate by origin + path
        seen: set[str] = set()
        for page in pages:
            parsed = urlparse(page.url)
            key = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            if key in seen:
                continue
            seen.add(key)
            self._test_cors(page.url)

        return self.findings

    def _test_cors(self, url: str) -> None:
        """Run CORS probes against a single URL."""
        parsed = urlparse(url)
        target_origin = f"{parsed.scheme}://{parsed.netloc}"

        # Probe 1: Evil attacker origin
        evil_origin = "https://evil-attacker.com"
        self._probe(url, evil_origin, "arbitrary attacker origin")

        # Probe 2: Null origin (often trusted by mistake — file://, sandboxed iframes)
        self._probe(url, "null", "null origin (sandboxed iframe / file://)")

        # Probe 3: Subdomain prefix attack (attacker.target.com)
        domain = parsed.hostname or ""
        subdomain_attack = f"{parsed.scheme}://attacker.{domain}"
        self._probe(url, subdomain_attack, f"subdomain prefix ({subdomain_attack})")

        # Probe 4: Suffix attack (target.com.evil.com)
        suffix_attack = f"{parsed.scheme}://{domain}.evil.com"
        self._probe(url, suffix_attack, f"domain suffix ({suffix_attack})")

    def _probe(self, url: str, origin: str, description: str) -> None:
        """Send a request with a crafted Origin header and analyse the response."""
        self._count_test()

        try:
            resp = http_utils.get(url, headers={"Origin": origin})
        except Exception:
            return

        acao = resp.headers.get("Access-Control-Allow-Origin", "")
        acac = resp.headers.get("Access-Control-Allow-Credentials", "").lower()

        if not acao:
            return  # No CORS headers — not vulnerable

        # Check 1: Wildcard with credentials (most dangerous)
        if acao == "*" and acac == "true":
            self._log_finding(Finding(
                vuln_type=VulnType.CORS_MISCONFIG,
                severity=Severity.CRITICAL,
                url=url,
                parameter="Access-Control-Allow-Origin",
                method="GET",
                payload=f"Origin: {origin}",
                evidence=(
                    f"CORS allows wildcard (*) with credentials. "
                    f"Access-Control-Allow-Origin: {acao}, "
                    f"Access-Control-Allow-Credentials: {acac}. "
                    f"Any website can make authenticated requests and read responses."
                ),
                remediation=_REMEDIATION,
            ))
            return

        # Check 2: Origin reflected back (server trusts any origin)
        if acao == origin or (origin == "null" and acao == "null"):
            severity = Severity.HIGH if acac == "true" else Severity.MEDIUM
            self._log_finding(Finding(
                vuln_type=VulnType.CORS_MISCONFIG,
                severity=severity,
                url=url,
                parameter="Access-Control-Allow-Origin",
                method="GET",
                payload=f"Origin: {origin}",
                evidence=(
                    f"CORS reflects {description} in Access-Control-Allow-Origin: {acao}. "
                    f"Credentials allowed: {acac or 'not set'}. "
                    f"{'Attacker can make authenticated cross-origin requests and read responses.' if acac == 'true' else 'Attacker can read unauthenticated cross-origin responses.'}"
                ),
                remediation=_REMEDIATION,
            ))
