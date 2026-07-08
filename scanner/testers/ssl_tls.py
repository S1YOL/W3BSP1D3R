from __future__ import annotations
"""
scanner/testers/ssl_tls.py
----------------------------
SSL/TLS certificate and configuration validation.

Security concept:
  Weak TLS configurations allow man-in-the-middle attacks, session hijacking,
  and data interception. Certificate issues (expired, self-signed, hostname
  mismatch) break the trust chain that HTTPS depends on.

Detection strategy:
  1. Connect to the target over SSL/TLS and inspect the certificate
  2. Check for expired certificates
  3. Check for hostname mismatches
  4. Check for self-signed certificates
  5. Inspect supported TLS versions and cipher suites
  6. Check for weak protocols (SSLv3, TLS 1.0, TLS 1.1)

OWASP ref: A02:2021 Cryptographic Failures
"""

import logging
import ssl
import socket
from datetime import datetime, timezone
from urllib.parse import urlparse

from scanner.crawler import CrawledPage
from scanner.reporting.models import Finding, Severity, VulnType
from scanner.testers.base import BaseTester

logger = logging.getLogger(__name__)

# Weak cipher suites that should not be used
_WEAK_CIPHERS = {
    "RC4", "DES", "3DES", "NULL", "EXPORT", "anon", "MD5",
    "RC2", "SEED", "IDEA", "CAMELLIA",
}

_REMEDIATION_CERT = (
    "Obtain a valid TLS certificate from a trusted Certificate Authority (CA). "
    "Use Let's Encrypt for free automated certificates. Ensure certificates "
    "are renewed before expiration. "
    "Ref: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/01-Testing_for_Weak_Transport_Layer_Security"
)

_REMEDIATION_PROTOCOL = (
    "Disable SSLv3, TLS 1.0, and TLS 1.1 on the server. Only allow TLS 1.2+ "
    "with strong cipher suites (AES-GCM, ChaCha20-Poly1305). "
    "Use Mozilla's SSL Configuration Generator: https://ssl-config.mozilla.org/ "
    "Ref: OWASP Transport Layer Security Cheat Sheet."
)


class SSLTLSTester(BaseTester):
    """Validates SSL/TLS certificate and configuration security."""

    def __init__(self) -> None:
        super().__init__(name="SSL/TLS Tester")

    def run(self, pages: list[CrawledPage]) -> list[Finding]:
        self.findings.clear()
        self._params_tested = 0

        if not pages:
            return self.findings

        # Extract unique HTTPS hosts
        hosts: set[tuple[str, int]] = set()
        for page in pages:
            parsed = urlparse(page.url)
            if parsed.scheme != "https":
                continue
            port = parsed.port or 443
            hosts.add((parsed.hostname, port))

        for hostname, port in hosts:
            self._check_certificate(hostname, port)
            self._check_weak_protocols(hostname, port)

        return self.findings

    def _check_certificate(self, hostname: str, port: int) -> None:
        """Inspect the TLS certificate for common issues."""
        self._count_test()

        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    protocol = ssock.version()
        except ssl.SSLCertVerificationError as exc:
            # Certificate validation failed — analyse the error
            error_msg = str(exc)

            if "CERTIFICATE_VERIFY_FAILED" in error_msg:
                if "self-signed" in error_msg.lower() or "self signed" in error_msg.lower():
                    self._log_finding(Finding(
                        vuln_type=VulnType.SSL_TLS,
                        severity=Severity.HIGH,
                        url=f"https://{hostname}:{port}",
                        parameter="TLS Certificate",
                        method="TLS handshake",
                        payload="(certificate inspection)",
                        evidence=(
                            f"Self-signed certificate detected: {error_msg[:200]}. "
                            "Browsers will show security warnings. MitM attacks are trivial "
                            "since any attacker can create their own self-signed cert."
                        ),
                        remediation=_REMEDIATION_CERT,
                    ))
                elif "expired" in error_msg.lower():
                    self._log_finding(Finding(
                        vuln_type=VulnType.SSL_TLS,
                        severity=Severity.HIGH,
                        url=f"https://{hostname}:{port}",
                        parameter="TLS Certificate",
                        method="TLS handshake",
                        payload="(certificate inspection)",
                        evidence=(
                            f"Expired certificate: {error_msg[:200]}. "
                            "Browsers will block or warn users, degrading trust."
                        ),
                        remediation=_REMEDIATION_CERT,
                    ))
                else:
                    self._log_finding(Finding(
                        vuln_type=VulnType.SSL_TLS,
                        severity=Severity.HIGH,
                        url=f"https://{hostname}:{port}",
                        parameter="TLS Certificate",
                        method="TLS handshake",
                        payload="(certificate inspection)",
                        evidence=f"Certificate verification failed: {error_msg[:300]}",
                        remediation=_REMEDIATION_CERT,
                    ))
            return
        except (socket.timeout, ConnectionRefusedError, OSError) as exc:
            logger.debug("SSL/TLS connection to %s:%d failed: %s", hostname, port, exc)
            return

        if not cert:
            return

        url = f"https://{hostname}:{port}"

        # Check expiration
        not_after = cert.get("notAfter", "")
        if not_after:
            try:
                expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                now = datetime.now(timezone.utc)
                days_left = (expiry - now).days

                if days_left < 0:
                    self._log_finding(Finding(
                        vuln_type=VulnType.SSL_TLS,
                        severity=Severity.HIGH,
                        url=url,
                        parameter="TLS Certificate Expiry",
                        method="TLS handshake",
                        payload="(certificate inspection)",
                        evidence=f"Certificate expired {abs(days_left)} days ago (expired: {not_after}).",
                        remediation=_REMEDIATION_CERT,
                    ))
                elif days_left < 30:
                    self._log_finding(Finding(
                        vuln_type=VulnType.SSL_TLS,
                        severity=Severity.MEDIUM,
                        url=url,
                        parameter="TLS Certificate Expiry",
                        method="TLS handshake",
                        payload="(certificate inspection)",
                        evidence=f"Certificate expires in {days_left} days ({not_after}). Renew soon.",
                        remediation=_REMEDIATION_CERT,
                    ))
            except ValueError:
                pass

        # Check cipher strength
        if cipher:
            cipher_name = cipher[0]
            for weak in _WEAK_CIPHERS:
                if weak in cipher_name.upper():
                    self._log_finding(Finding(
                        vuln_type=VulnType.SSL_TLS,
                        severity=Severity.HIGH,
                        url=url,
                        parameter="TLS Cipher Suite",
                        method="TLS handshake",
                        payload="(cipher negotiation)",
                        evidence=(
                            f"Weak cipher suite negotiated: {cipher_name}. "
                            f"Protocol: {protocol}. "
                            f"Weak ciphers can be broken by attackers to decrypt traffic."
                        ),
                        remediation=_REMEDIATION_PROTOCOL,
                    ))
                    break

        # Check for old TLS version
        if protocol and protocol in ("SSLv3", "TLSv1", "TLSv1.1"):
            self._log_finding(Finding(
                vuln_type=VulnType.SSL_TLS,
                severity=Severity.MEDIUM,
                url=url,
                parameter="TLS Protocol Version",
                method="TLS handshake",
                payload="(protocol negotiation)",
                evidence=(
                    f"Outdated TLS protocol: {protocol}. "
                    "TLS 1.0 and 1.1 have known vulnerabilities (BEAST, POODLE). "
                    "Major browsers have deprecated these versions."
                ),
                remediation=_REMEDIATION_PROTOCOL,
            ))

    def _check_weak_protocols(self, hostname: str, port: int) -> None:
        """Actively probe for deprecated protocol support."""
        # These constants may not exist in newer Python versions that have
        # removed legacy TLS support entirely (Python 3.10+).
        deprecated: list[tuple] = []
        for attr, name in [("PROTOCOL_TLSv1", "TLSv1.0"), ("PROTOCOL_TLSv1_1", "TLSv1.1")]:
            const = getattr(ssl, attr, None)
            if const is not None:
                deprecated.append((const, name))

        for protocol_const, protocol_name in deprecated:
            self._count_test()
            try:
                ctx = ssl.SSLContext(protocol_const)
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                with socket.create_connection((hostname, port), timeout=5) as sock:
                    with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                        # If we get here, the server accepted the deprecated protocol
                        self._log_finding(Finding(
                            vuln_type=VulnType.SSL_TLS,
                            severity=Severity.MEDIUM,
                            url=f"https://{hostname}:{port}",
                            parameter="TLS Protocol Support",
                            method="TLS handshake",
                            payload=f"(connected using {protocol_name})",
                            evidence=(
                                f"Server accepts deprecated protocol {protocol_name}. "
                                "This protocol has known vulnerabilities and should be disabled. "
                                "Attackers can force a downgrade to exploit protocol weaknesses."
                            ),
                            remediation=_REMEDIATION_PROTOCOL,
                        ))
            except (ssl.SSLError, OSError, AttributeError):
                pass  # Protocol not supported — good
