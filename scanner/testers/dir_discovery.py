from __future__ import annotations
"""
scanner/testers/dir_discovery.py
----------------------------------
Directory and endpoint discovery — finds hidden paths, admin panels,
backup files, API endpoints, and exposed configuration that aren't
linked from the public site.

This is one of the most valuable recon techniques in authorised pentesting.
Many critical vulnerabilities exist on endpoints that are deployed but not
linked — admin panels, debug pages, API docs, backup archives, and
version control artifacts.

Detection approach:
  - Probes a wordlist of common paths against the target
  - Filters by status code (200, 301, 302, 403 are interesting)
  - Categorises findings by risk level
  - Skips paths that return the same generic 404 page (custom 404 detection)
"""

import logging
from urllib.parse import urljoin, urlparse

from scanner.testers.base import BaseTester
from scanner.crawler import CrawledPage
from scanner.reporting.models import Confidence, Finding, Severity, VulnType
from scanner.utils import http as http_utils

logger = logging.getLogger(__name__)


# Paths that are expected to be public by design — being reachable is normal,
# not a finding worth alarming a corporate reader over. Reported at Low/Info.
_EXPECTED_PUBLIC_PATHS = {
    "/robots.txt", "/sitemap.xml", "/sitemap_index.xml", "/security.txt",
    "/.well-known/security.txt", "/humans.txt", "/favicon.ico",
    "/crossdomain.xml", "/clientaccesspolicy.xml",
    "/.well-known/openid-configuration",
}


def _neutral_label(description: str) -> str:
    """Strip a trailing verdict word ("exposed"/"accessible"/"found") from a
    path description so an accurate accessibility statement can be attached.
    e.g. "Git config exposed" -> "Git config"."""
    lowered = description.lower()
    for suffix in (" exposed", " accessible", " found", " is exposed"):
        if lowered.endswith(suffix):
            return description[: -len(suffix)]
    return description

# Paths categorised by severity
_CRITICAL_PATHS = [
    # Version control — full source code exposure
    ("/.git/HEAD", "Git repository exposed"),
    ("/.git/config", "Git config exposed"),
    ("/.svn/entries", "SVN repository exposed"),
    ("/.hg/dirstate", "Mercurial repository exposed"),
    # Environment / secrets
    ("/.env", "Environment file exposed"),
    ("/.env.backup", "Environment backup exposed"),
    ("/.env.local", "Local environment file exposed"),
    ("/.env.production", "Production environment file exposed"),
    ("/wp-config.php.bak", "WordPress config backup exposed"),
    ("/config.php.bak", "PHP config backup exposed"),
    ("/web.config.bak", "IIS config backup exposed"),
    # Database dumps
    ("/dump.sql", "SQL dump exposed"),
    ("/database.sql", "Database dump exposed"),
    ("/db.sql", "Database dump exposed"),
    ("/backup.sql", "SQL backup exposed"),
    ("/data.sql", "Data dump exposed"),
]

_HIGH_PATHS = [
    # Admin panels
    ("/admin", "Admin panel found"),
    ("/admin/", "Admin panel found"),
    ("/administrator", "Admin panel found"),
    ("/admin/login", "Admin login found"),
    ("/wp-admin", "WordPress admin found"),
    ("/wp-login.php", "WordPress login found"),
    ("/manager", "Manager panel found"),
    ("/cpanel", "cPanel found"),
    ("/phpmyadmin", "phpMyAdmin found"),
    ("/phpmyadmin/", "phpMyAdmin found"),
    ("/adminer.php", "Adminer database tool found"),
    ("/dashboard", "Dashboard found"),
    ("/panel", "Control panel found"),
    # Debug / diagnostics
    ("/debug", "Debug endpoint found"),
    ("/debug/", "Debug endpoint found"),
    ("/server-status", "Apache server-status exposed"),
    ("/server-info", "Apache server-info exposed"),
    ("/phpinfo.php", "PHP info page exposed"),
    ("/info.php", "PHP info page exposed"),
    ("/elmah.axd", ".NET error log exposed"),
    ("/_profiler", "Symfony profiler exposed"),
    ("/actuator", "Spring Boot actuator exposed"),
    ("/actuator/health", "Spring actuator health exposed"),
    ("/actuator/env", "Spring actuator env exposed"),
    # API documentation
    ("/swagger-ui.html", "Swagger API docs exposed"),
    ("/swagger-ui/", "Swagger API docs exposed"),
    ("/api-docs", "API documentation exposed"),
    ("/graphql", "GraphQL endpoint found"),
    ("/graphiql", "GraphiQL IDE exposed"),
    ("/.well-known/openid-configuration", "OpenID config exposed"),
    # Backups
    ("/backup", "Backup directory found"),
    ("/backup/", "Backup directory found"),
    ("/backups", "Backup directory found"),
    ("/old", "Old files directory found"),
    ("/temp", "Temp directory found"),
    ("/tmp", "Temp directory found"),
]

_MEDIUM_PATHS = [
    # Common CMS / framework paths
    ("/robots.txt", "Robots.txt found"),
    ("/sitemap.xml", "Sitemap found"),
    ("/crossdomain.xml", "Flash crossdomain policy found"),
    ("/clientaccesspolicy.xml", "Silverlight access policy found"),
    ("/security.txt", "Security policy found"),
    ("/.well-known/security.txt", "Security policy found"),
    # Config files
    ("/config", "Config directory found"),
    ("/config/", "Config directory found"),
    ("/settings", "Settings endpoint found"),
    ("/web.config", "IIS config found"),
    ("/nginx.conf", "Nginx config exposed"),
    ("/htaccess", "htaccess exposed"),
    ("/.htaccess", "htaccess exposed"),
    ("/.htpasswd", "htpasswd exposed"),
    # Log files
    ("/logs", "Log directory found"),
    ("/logs/", "Log directory found"),
    ("/log", "Log directory found"),
    ("/error.log", "Error log exposed"),
    ("/access.log", "Access log exposed"),
    ("/debug.log", "Debug log exposed"),
    # Common API paths
    ("/api", "API endpoint found"),
    ("/api/", "API endpoint found"),
    ("/api/v1", "API v1 endpoint found"),
    ("/api/v2", "API v2 endpoint found"),
    ("/rest", "REST API found"),
    ("/v1", "API v1 found"),
    ("/v2", "API v2 found"),
    # Common framework paths
    ("/console", "Console endpoint found"),
    ("/status", "Status page found"),
    ("/health", "Health check found"),
    ("/healthcheck", "Health check found"),
    ("/metrics", "Metrics endpoint found"),
    ("/trace", "Trace endpoint found"),
    ("/info", "Info endpoint found"),
    # Install / setup
    ("/install", "Install page found"),
    ("/setup", "Setup page found"),
    ("/install.php", "PHP installer found"),
    ("/setup.php", "PHP setup found"),
]

# Status codes we consider interesting (not 404)
_INTERESTING_STATUSES = {200, 201, 301, 302, 307, 308, 401, 403}

# Minimum response size to consider valid (avoids false positives from
# custom 404 pages that return 200)
_MIN_CONTENT_LENGTH = 50


class DirDiscoveryTester(BaseTester):
    """
    Discover hidden directories, admin panels, backup files, and
    exposed configuration endpoints.
    """

    def __init__(self) -> None:
        super().__init__(name="Directory Discovery")

    def run(self, pages: list[CrawledPage]) -> list[Finding]:
        if not pages:
            return self.findings

        pages = self._filter_pages_by_scope(pages)
        base_url = pages[0].url
        parsed = urlparse(base_url)
        origin = f"{parsed.scheme}://{parsed.netloc}"

        # Get a baseline 404 response to detect custom 404 pages
        baseline_404 = self._get_404_baseline(origin)

        # Probe all paths
        all_paths = (
            [(p, d, Severity.CRITICAL) for p, d in _CRITICAL_PATHS] +
            [(p, d, Severity.HIGH) for p, d in _HIGH_PATHS] +
            [(p, d, Severity.MEDIUM) for p, d in _MEDIUM_PATHS]
        )

        for path, description, severity in all_paths:
            self._count_test()
            probe_url = origin + path

            try:
                resp = http_utils.get(probe_url)
            except Exception:
                continue

            if resp.status_code not in _INTERESTING_STATUSES:
                continue

            # Skip if response matches our 404 baseline (custom 404 page)
            if baseline_404 and self._is_custom_404(resp, baseline_404):
                continue

            # Skip tiny responses (likely empty or error stubs)
            if len(resp.content) < _MIN_CONTENT_LENGTH:
                continue

            label = _neutral_label(description)

            if resp.status_code in (401, 403):
                # Access-restricted: the resource is NOT publicly readable. This
                # is recon signal (the server handles this path specifically),
                # not an exposure — word it accurately and rate it low.
                actual_severity = Severity.LOW
                confidence = Confidence.TENTATIVE
                vuln_type = "Restricted Path Detected"
                evidence = (
                    f"{label} present but access-restricted (HTTP {resp.status_code}). "
                    f"The server applies specific access controls to this path "
                    f"(its response differs from the generic catch-all), so the path "
                    f"is recognised/blocked rather than simply non-existent. "
                    f"It is NOT publicly readable. Response: {len(resp.content)} bytes."
                )
                remediation = (
                    f"Access to {path} is already restricted (HTTP {resp.status_code}); "
                    "no immediate exposure exists. To reduce information disclosure, "
                    "consider returning HTTP 404 instead of 401/403 so the path's "
                    "existence cannot be confirmed by attackers."
                )
            elif path in _EXPECTED_PUBLIC_PATHS:
                # Reachable, but public by design (robots.txt, sitemap, etc.).
                # Report as informational so it doesn't inflate the risk picture.
                actual_severity = Severity.LOW
                confidence = Confidence.TENTATIVE
                vuln_type = "Public Resource Present"
                evidence = (
                    f"{label} is present (HTTP {resp.status_code}). This resource "
                    f"is expected to be public and is informational only — review "
                    f"its contents for unintended disclosure. Response: "
                    f"{len(resp.content)} bytes."
                )
                remediation = (
                    f"No action required for the presence of {path} itself. "
                    "Review its contents to ensure it does not disclose internal "
                    "hostnames, staging paths, or other sensitive details."
                )
            else:
                # Publicly accessible (2xx): this is a genuine exposure.
                actual_severity = severity
                confidence = Confidence.FIRM
                vuln_type = "Sensitive Path Accessible"
                evidence = (
                    f"{label} is publicly accessible (HTTP {resp.status_code}). "
                    f"Response: {len(resp.content)} bytes."
                )
                remediation = (
                    f"Remove or restrict public access to {path}. "
                    "Ensure sensitive files, admin panels, and debug endpoints "
                    "are not reachable in production. Use web server configuration "
                    "to block access to backup files, version control directories, "
                    "and configuration files."
                )

            self._log_finding(Finding(
                vuln_type=vuln_type,
                severity=actual_severity,
                url=probe_url,
                parameter=path,
                method="GET",
                payload=f"GET {path}",
                evidence=evidence,
                remediation=remediation,
                confidence=confidence,
            ))

        return self.findings

    def _get_404_baseline(self, origin: str) -> str | None:
        """Fetch a URL that shouldn't exist to fingerprint the 404 page."""
        try:
            resp = http_utils.get(origin + "/w3bsp1d3r-nonexistent-path-404-check")
            if resp.status_code == 200 and len(resp.content) > 100:
                # Server returns 200 for missing pages (custom 404)
                return resp.text[:500]
        except Exception:
            pass
        return None

    def _is_custom_404(self, resp, baseline_404: str) -> bool:
        """Check if a response matches the custom 404 baseline."""
        if resp.status_code != 200:
            return False
        resp_sample = resp.text[:500]
        # Simple similarity check — if >80% of the baseline matches
        if baseline_404 and resp_sample:
            matches = sum(1 for a, b in zip(resp_sample, baseline_404) if a == b)
            similarity = matches / max(len(baseline_404), 1)
            return similarity > 0.8
        return False
