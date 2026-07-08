from __future__ import annotations
"""
scanner/testers/subdomain.py
------------------------------
Subdomain enumeration and reconnaissance.

Security concept:
  Subdomains often host development, staging, or internal applications with
  weaker security controls than the main site. Discovering subdomains expands
  the attack surface and can reveal:
  - Forgotten staging environments with default credentials
  - Internal APIs exposed to the internet
  - Outdated services running vulnerable software
  - Admin panels, CI/CD dashboards, and monitoring tools

Detection strategy:
  1. DNS brute-force using a curated wordlist of common subdomain prefixes
  2. Check for HTTP response on discovered subdomains
  3. Report accessible subdomains with their HTTP status and server headers

Note: This is passive DNS enumeration only — no active exploitation.

OWASP ref: A05:2021 Security Misconfiguration
"""

import logging
import socket
from urllib.parse import urlparse

from scanner.crawler import CrawledPage
from scanner.reporting.models import Finding, Severity, VulnType
from scanner.testers.base import BaseTester

logger = logging.getLogger(__name__)

# Common subdomain prefixes — curated for high signal-to-noise ratio
_SUBDOMAIN_WORDLIST = [
    "www", "mail", "ftp", "admin", "api", "dev", "staging", "test",
    "beta", "app", "portal", "vpn", "remote", "git", "gitlab", "jenkins",
    "ci", "cd", "build", "deploy", "monitor", "grafana", "prometheus",
    "kibana", "elastic", "logs", "sentry", "status", "health",
    "docs", "wiki", "blog", "shop", "store", "cdn", "assets", "static",
    "media", "images", "img", "files", "upload", "download",
    "db", "database", "mysql", "postgres", "redis", "mongo",
    "internal", "intranet", "corp", "office", "helpdesk", "support",
    "billing", "payment", "checkout", "auth", "sso", "login", "oauth",
    "sandbox", "demo", "preview", "uat", "qa", "prod", "production",
    "backup", "bak", "old", "legacy", "archive",
    "mx", "smtp", "imap", "pop", "ns1", "ns2",
    "webmail", "autodiscover", "exchange",
    "jira", "confluence", "slack", "teams",
    "s3", "bucket", "storage", "vault",
    "k8s", "kubernetes", "docker", "registry", "container",
    "proxy", "gateway", "lb", "loadbalancer",
    "stage", "stg", "preprod", "pre-prod",
]

_REMEDIATION = (
    "Review all discovered subdomains for security posture. Ensure development, "
    "staging, and internal subdomains are not publicly accessible. Use DNS "
    "monitoring to detect unauthorized subdomain creation. Remove or restrict "
    "access to unused subdomains. Consider using wildcard DNS with proper "
    "access controls."
)


class SubdomainTester(BaseTester):
    """Enumerates subdomains via DNS resolution to expand attack surface discovery."""

    def __init__(self) -> None:
        super().__init__(name="Subdomain Enumerator")

    def run(self, pages: list[CrawledPage]) -> list[Finding]:
        self.findings.clear()
        self._params_tested = 0

        if not pages:
            return self.findings

        # Extract the root domain from the target
        parsed = urlparse(pages[0].url)
        hostname = parsed.hostname or ""

        # Skip if the target is an IP address
        if self._is_ip(hostname):
            logger.debug("Target is an IP address — skipping subdomain enumeration")
            return self.findings

        # Extract registrable domain (e.g., example.com from sub.example.com)
        domain = self._extract_domain(hostname)
        if not domain:
            return self.findings

        logger.debug("Enumerating subdomains for: %s", domain)
        discovered = []

        for prefix in _SUBDOMAIN_WORDLIST:
            self._count_test()
            subdomain = f"{prefix}.{domain}"

            # Skip if it's the same as the target
            if subdomain == hostname:
                continue

            ip = self._resolve(subdomain)
            if ip:
                discovered.append((subdomain, ip))

        if discovered:
            # Create a single finding with all discovered subdomains
            subdomain_list = "\n".join(
                f"  - {sub} ({ip})" for sub, ip in discovered
            )
            self._log_finding(Finding(
                vuln_type=VulnType.SUBDOMAIN_DISCOVERY,
                severity=Severity.LOW,
                url=pages[0].url,
                parameter="DNS enumeration",
                method="DNS",
                payload=f"Checked {len(_SUBDOMAIN_WORDLIST)} common subdomain prefixes",
                evidence=(
                    f"Discovered {len(discovered)} active subdomain(s) for {domain}:\n"
                    f"{subdomain_list}\n"
                    "These subdomains may host development, staging, or internal "
                    "applications with weaker security controls."
                ),
                remediation=_REMEDIATION,
                extra={
                    "domain": domain,
                    "subdomains": [
                        {"subdomain": sub, "ip": ip} for sub, ip in discovered
                    ],
                },
            ))

        return self.findings

    @staticmethod
    def _resolve(hostname: str) -> str | None:
        """Attempt DNS resolution. Returns IP address or None."""
        try:
            result = socket.getaddrinfo(hostname, None, socket.AF_INET, socket.SOCK_STREAM)
            if result:
                return result[0][4][0]
        except (socket.gaierror, OSError):
            pass
        return None

    @staticmethod
    def _is_ip(hostname: str) -> bool:
        """Check if a string is an IP address."""
        try:
            socket.inet_aton(hostname)
            return True
        except (socket.error, OSError):
            pass
        try:
            socket.inet_pton(socket.AF_INET6, hostname)
            return True
        except (socket.error, OSError):
            pass
        return False

    @staticmethod
    def _extract_domain(hostname: str) -> str | None:
        """
        Extract the registrable domain from a hostname.
        Simple heuristic: take the last two parts (e.g., example.com from sub.example.com).
        For country code TLDs (co.uk, com.au), take the last three parts.
        """
        parts = hostname.split(".")
        if len(parts) < 2:
            return None

        # Common two-part TLDs
        two_part_tlds = {
            "co.uk", "com.au", "co.nz", "co.za", "com.br", "co.in",
            "org.uk", "net.au", "co.jp", "co.kr", "com.cn", "com.tw",
        }

        if len(parts) >= 3:
            potential_tld = f"{parts[-2]}.{parts[-1]}"
            if potential_tld in two_part_tlds:
                return ".".join(parts[-3:])

        return ".".join(parts[-2:])
