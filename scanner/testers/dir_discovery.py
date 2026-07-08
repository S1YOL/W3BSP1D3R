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
from scanner.reporting.models import Finding, Severity, VulnType
from scanner.utils import http as http_utils

logger = logging.getLogger(__name__)

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

            # Determine severity based on status code
            if resp.status_code in (401, 403):
                # Protected but exists — still interesting, lower severity
                actual_severity = Severity.MEDIUM if severity == Severity.CRITICAL else Severity.LOW
                status_note = f" (HTTP {resp.status_code} — protected but exists)"
            else:
                actual_severity = severity
                status_note = f" (HTTP {resp.status_code})"

            self._log_finding(Finding(
                vuln_type="Directory/Endpoint Discovery",
                severity=actual_severity,
                url=probe_url,
                parameter=path,
                method="GET",
                payload=f"GET {path}",
                evidence=f"{description}{status_note}. "
                         f"Response: {len(resp.content)} bytes.",
                remediation=(
                    f"Remove or restrict access to {path}. "
                    "Ensure sensitive files, admin panels, and debug endpoints "
                    "are not accessible in production. Use web server configuration "
                    "to block access to backup files, version control directories, "
                    "and configuration files."
                ),
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
