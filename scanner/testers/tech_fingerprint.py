from __future__ import annotations
"""
scanner/testers/tech_fingerprint.py
--------------------------------------
Technology fingerprinting — identifies web server software, frameworks,
CMS platforms, and programming languages used by the target.

Why this matters for authorised testing:
  - Knowing the tech stack narrows which CVEs and attack vectors apply
  - Outdated software versions are a top source of vulnerabilities
  - Server headers often leak exact version numbers
  - Framework-specific defaults may expose admin panels or debug modes

Detection approach:
  - HTTP response headers (Server, X-Powered-By, X-AspNet-Version, etc.)
  - HTML meta tags and generators
  - Known framework-specific paths and cookies
  - Error page fingerprints
  - JavaScript library detection
"""

import logging
import re
from urllib.parse import urlparse

from scanner.testers.base import BaseTester
from scanner.crawler import CrawledPage
from scanner.reporting.models import Finding, Severity
from scanner.utils import http as http_utils

logger = logging.getLogger(__name__)

# Response headers that leak technology information
_TECH_HEADERS = [
    "Server",
    "X-Powered-By",
    "X-AspNet-Version",
    "X-AspNetMvc-Version",
    "X-Generator",
    "X-Drupal-Cache",
    "X-Drupal-Dynamic-Cache",
    "X-Varnish",
    "X-Cache",
    "X-Runtime",           # Ruby on Rails
    "X-Request-Id",        # Rails / Phoenix
    "X-Turbo-Charged-By",  # LiteSpeed
    "Via",
    "X-Content-Type-Options",
]

# Known framework indicators in HTML
_HTML_INDICATORS = [
    # (regex pattern, technology name)
    (r'<meta\s+name="generator"\s+content="([^"]+)"', "CMS/Generator"),
    (r'wp-content/', "WordPress"),
    (r'wp-includes/', "WordPress"),
    (r'/wp-json/', "WordPress REST API"),
    (r'Joomla', "Joomla"),
    (r'drupal\.js', "Drupal"),
    (r'sites/default/files', "Drupal"),
    (r'content="Drupal', "Drupal"),
    (r'csrfmiddlewaretoken', "Django"),
    (r'__django_', "Django"),
    (r'laravel_session', "Laravel"),
    (r'XSRF-TOKEN.*laravel', "Laravel"),
    (r'<meta\s+name="csrf-token"\s+content="[^"]+"', "Rails/Laravel"),
    (r'rails-ujs\b', "Ruby on Rails"),
    (r'__next', "Next.js"),
    (r'__nuxt', "Nuxt.js"),
    (r'_next/static', "Next.js"),
    (r'react-root\b|reactroot\b|__react', "React"),
    (r'ng-version=', "Angular"),
    (r'ng-app\b|ng-controller\b', "AngularJS"),
    (r'ember-view\b', "Ember.js"),
    (r'data-vue\b|__vue__', "Vue.js"),
    (r'Powered by <a[^>]*>Express', "Express.js"),
    (r'<meta\s+name="author"\s+content="Jellyfin"', "Jellyfin"),
    (r'emby\b|jellyfin\b', "Jellyfin/Emby"),
    (r'plex\.tv|plex-token', "Plex"),
]

# Cookie names that indicate specific technologies
_TECH_COOKIES = {
    "PHPSESSID": "PHP",
    "JSESSIONID": "Java (Tomcat/Spring)",
    "ASP.NET_SessionId": "ASP.NET",
    ".AspNetCore.": "ASP.NET Core",
    "laravel_session": "Laravel (PHP)",
    "XSRF-TOKEN": "Laravel / Angular",
    "csrftoken": "Django (Python)",
    "sessionid": "Django (Python)",
    "_rails_": "Ruby on Rails",
    "rack.session": "Ruby (Rack)",
    "connect.sid": "Node.js (Express)",
    "express:sess": "Node.js (Express)",
    "wordpress_": "WordPress",
    "wp-": "WordPress",
    "joomla_": "Joomla",
}

# Framework-specific paths to probe
_TECH_PATHS = [
    ("/wp-login.php", "WordPress"),
    ("/wp-includes/js/wp-embed.min.js", "WordPress"),
    ("/administrator/index.php", "Joomla"),
    ("/user/login", "Drupal"),
    ("/rails/info", "Ruby on Rails (dev mode)"),
    ("/elmah.axd", "ASP.NET (ELMAH)"),
    ("/trace.axd", "ASP.NET (Trace)"),
    ("/actuator/info", "Spring Boot"),
    ("/api/system/info", "Jellyfin"),
]


class TechFingerprintTester(BaseTester):
    """Identify technologies, frameworks, and software versions on the target."""

    def __init__(self) -> None:
        super().__init__(name="Technology Fingerprinting")
        self._detected: dict[str, str] = {}  # tech → evidence

    def run(self, pages: list[CrawledPage]) -> list[Finding]:
        if not pages:
            return self.findings

        pages = self._filter_pages_by_scope(pages)
        base_url = pages[0].url
        parsed = urlparse(base_url)
        origin = f"{parsed.scheme}://{parsed.netloc}"

        # 1. Check response headers
        self._check_headers(origin)

        # 2. Check HTML content of crawled pages
        for page in pages[:10]:
            self._check_html(page.url)

        # 3. Check cookies
        self._check_cookies()

        # 4. Probe framework-specific paths
        self._check_tech_paths(origin)

        # Report all detected technologies
        if self._detected:
            tech_list = []
            for tech, evidence in self._detected.items():
                tech_list.append(f"{tech}: {evidence}")

            severity = Severity.LOW
            # Upgrade severity if version numbers are exposed
            for tech, evidence in self._detected.items():
                if re.search(r'\d+\.\d+', evidence):
                    severity = Severity.MEDIUM
                    break

            self._log_finding(Finding(
                vuln_type="Technology Stack Detected",
                severity=severity,
                url=origin,
                parameter="Multiple indicators",
                method="GET",
                payload="Header analysis + HTML fingerprinting + path probing",
                evidence=(
                    f"Detected {len(self._detected)} technologies: "
                    + " | ".join(tech_list)
                ),
                remediation=(
                    "Remove or obscure technology identifiers from HTTP headers "
                    "(Server, X-Powered-By). Disable version disclosure in your "
                    "web server and framework configuration. "
                    "Apache: ServerTokens Prod, ServerSignature Off. "
                    "Nginx: server_tokens off. "
                    "PHP: expose_php = Off in php.ini. "
                    "While security through obscurity alone is insufficient, "
                    "reducing information disclosure makes reconnaissance harder."
                ),
            ))

        return self.findings

    def _add_tech(self, name: str, evidence: str) -> None:
        """Register a detected technology (deduplicates)."""
        if name not in self._detected:
            self._detected[name] = evidence
            logger.debug("Detected technology: %s (%s)", name, evidence)

    def _check_headers(self, origin: str) -> None:
        """Check response headers for technology leaks."""
        self._count_test()
        try:
            resp = http_utils.get(origin + "/")
        except Exception:
            return

        for header in _TECH_HEADERS:
            value = resp.headers.get(header)
            if value:
                self._add_tech(
                    f"{header} header",
                    f"{header}: {value}",
                )

    def _check_html(self, url: str) -> None:
        """Check HTML content for framework indicators."""
        self._count_test()
        try:
            resp = http_utils.get(url)
        except Exception:
            return

        body = resp.text
        for pattern, tech_name in _HTML_INDICATORS:
            match = re.search(pattern, body, re.IGNORECASE)
            if match:
                matched_text = match.group(0)[:100]
                self._add_tech(tech_name, f"HTML match: {matched_text}")

    def _check_cookies(self) -> None:
        """Check session cookies for technology indicators."""
        self._count_test()
        session = http_utils.get_session()
        for cookie in session.cookies:
            for cookie_pattern, tech_name in _TECH_COOKIES.items():
                if cookie_pattern.lower() in cookie.name.lower():
                    self._add_tech(tech_name, f"Cookie: {cookie.name}")

    def _check_tech_paths(self, origin: str) -> None:
        """Probe known framework-specific paths."""
        for path, tech_name in _TECH_PATHS:
            self._count_test()
            try:
                resp = http_utils.get(origin + path)
                if resp.status_code == 200 and len(resp.content) > 50:
                    self._add_tech(tech_name, f"Path exists: {path} (HTTP 200)")
            except Exception:
                continue
