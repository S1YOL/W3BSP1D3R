from __future__ import annotations
"""
scanner/testers/sensitive_files.py
-------------------------------------
Sensitive file and directory discovery.

Probes for commonly exposed files that leak source code, credentials,
configuration, or grant access to admin interfaces. This is one of the
most impactful checks in Acunetix, Nikto, and enterprise audit tools.

Categories:
  - Source control exposure  (.git, .svn, .hg)
  - Credentials / config     (.env, wp-config.php, database.yml)
  - Backups                  (*.zip, *.sql, *.bak)
  - Debug / info pages       (phpinfo.php, server-status)
  - Admin interfaces         (/admin, /phpmyadmin, /adminer)
  - Server config            (.htaccess, .htpasswd, web.config)
  - Container / cloud        (Dockerfile, docker-compose.yml)
  - Package manifests        (package.json, composer.json)

OWASP ref: A05:2021 Security Misconfiguration, A01:2021 Broken Access Control
"""

import logging
from typing import NamedTuple
from urllib.parse import urljoin, urlparse

from scanner.crawler import CrawledPage
from scanner.reporting.models import Finding, Severity, VulnType
from scanner.testers.base import BaseTester
from scanner.utils import http as http_utils

logger = logging.getLogger(__name__)

_REMEDIATION = (
    "Remove or restrict access to sensitive files using web server access controls. "
    "Never deploy source control directories, .env files, or backup archives to "
    "production. Use .gitignore / .dockerignore to prevent accidental exposure. "
    "Ref: OWASP Configuration and Deployment Management Testing."
)


class SensitiveTarget(NamedTuple):
    path:         str    # URL path to probe
    severity:     str
    description:  str
    confirm_text: str = ""   # must appear in body to confirm (reduces false positives)


SENSITIVE_TARGETS: list[SensitiveTarget] = [
    # --- Source control ---
    SensitiveTarget("/.git/HEAD",           Severity.CRITICAL, "Git repo HEAD exposed",        "ref:"),
    SensitiveTarget("/.git/config",         Severity.CRITICAL, "Git config exposed",           "[core]"),
    SensitiveTarget("/.git/COMMIT_EDITMSG", Severity.HIGH,     "Git commit message exposed"),
    SensitiveTarget("/.git/index",          Severity.HIGH,     "Git index exposed"),
    SensitiveTarget("/.svn/entries",        Severity.HIGH,     "SVN repo exposed",             "svn"),
    SensitiveTarget("/.hg/store",           Severity.HIGH,     "Mercurial repo exposed"),

    # --- Environment / credentials ---
    SensitiveTarget("/.env",                Severity.CRITICAL, ".env file exposed",            "APP_"),
    SensitiveTarget("/.env.production",     Severity.CRITICAL, ".env.production exposed",      "APP_"),
    SensitiveTarget("/.env.local",          Severity.CRITICAL, ".env.local exposed",           "APP_"),
    SensitiveTarget("/.env.backup",         Severity.CRITICAL, ".env.backup exposed",          "APP_"),
    SensitiveTarget("/.env.example",        Severity.MEDIUM,   ".env.example (may reveal key names)", "APP_"),
    SensitiveTarget("/wp-config.php",       Severity.CRITICAL, "WordPress config exposed",     "DB_"),
    SensitiveTarget("/config.php",          Severity.HIGH,     "config.php exposed",           "<?php"),
    SensitiveTarget("/configuration.php",   Severity.HIGH,     "Joomla config exposed",        "<?php"),
    SensitiveTarget("/config/database.yml", Severity.CRITICAL, "Rails DB config exposed",      "adapter:"),
    SensitiveTarget("/database.yml",        Severity.HIGH,     "database.yml exposed",         "adapter:"),
    SensitiveTarget("/config.yml",          Severity.HIGH,     "config.yml exposed"),
    SensitiveTarget("/settings.py",         Severity.HIGH,     "Django settings exposed",      "SECRET_KEY"),
    SensitiveTarget("/application.properties", Severity.HIGH,  "Spring Boot props exposed",    "spring."),
    SensitiveTarget("/appsettings.json",    Severity.HIGH,     "ASP.NET appsettings exposed",  "ConnectionStrings"),
    SensitiveTarget("/secrets.yml",         Severity.CRITICAL, "secrets.yml exposed",          "secret_key_base"),
    SensitiveTarget("/credentials.json",    Severity.CRITICAL, "credentials.json exposed"),

    # --- Backup files ---
    SensitiveTarget("/backup.zip",          Severity.CRITICAL, "Site backup archive exposed"),
    SensitiveTarget("/backup.tar.gz",       Severity.CRITICAL, "Site backup archive exposed"),
    SensitiveTarget("/backup.sql",          Severity.CRITICAL, "SQL backup exposed",           "INSERT INTO"),
    SensitiveTarget("/db.sql",              Severity.CRITICAL, "SQL dump exposed",             "INSERT INTO"),
    SensitiveTarget("/dump.sql",            Severity.CRITICAL, "SQL dump exposed",             "INSERT INTO"),
    SensitiveTarget("/site.zip",            Severity.CRITICAL, "Site archive exposed"),
    SensitiveTarget("/www.zip",             Severity.HIGH,     "Site archive exposed"),
    SensitiveTarget("/backup.bak",          Severity.HIGH,     "Backup file exposed"),
    SensitiveTarget("/index.php.bak",       Severity.HIGH,     "PHP backup file exposed",      "<?php"),
    SensitiveTarget("/web.config.bak",      Severity.HIGH,     "web.config backup exposed",    "<configuration"),

    # --- Debug / info pages ---
    SensitiveTarget("/phpinfo.php",         Severity.HIGH,     "phpinfo() page exposed",       "phpinfo"),
    SensitiveTarget("/info.php",            Severity.HIGH,     "phpinfo() page exposed",       "phpinfo"),
    SensitiveTarget("/test.php",            Severity.MEDIUM,   "PHP test page exposed"),
    SensitiveTarget("/debug.php",           Severity.HIGH,     "Debug page exposed"),
    SensitiveTarget("/debug",               Severity.MEDIUM,   "Debug endpoint"),
    SensitiveTarget("/_profiler",           Severity.MEDIUM,   "Symfony profiler exposed"),
    SensitiveTarget("/telescope",           Severity.HIGH,     "Laravel Telescope exposed"),
    SensitiveTarget("/horizon",             Severity.HIGH,     "Laravel Horizon exposed"),

    # --- Admin interfaces ---
    SensitiveTarget("/admin/",              Severity.MEDIUM,   "Admin panel accessible"),
    SensitiveTarget("/administrator/",      Severity.MEDIUM,   "Joomla admin panel"),
    SensitiveTarget("/phpmyadmin/",         Severity.HIGH,     "phpMyAdmin accessible"),
    SensitiveTarget("/pma/",               Severity.HIGH,     "phpMyAdmin (pma) accessible"),
    SensitiveTarget("/wp-admin/",           Severity.MEDIUM,   "WordPress admin panel"),
    SensitiveTarget("/wp-login.php",        Severity.MEDIUM,   "WordPress login page"),
    SensitiveTarget("/adminer.php",         Severity.HIGH,     "Adminer DB tool exposed"),
    SensitiveTarget("/adminer/",            Severity.HIGH,     "Adminer DB tool exposed"),
    SensitiveTarget("/manager/html",        Severity.HIGH,     "Tomcat Manager exposed"),
    SensitiveTarget("/console",             Severity.HIGH,     "Web console accessible"),

    # --- Server config ---
    SensitiveTarget("/.htaccess",           Severity.MEDIUM,   ".htaccess exposed"),
    SensitiveTarget("/.htpasswd",           Severity.CRITICAL, ".htpasswd exposed",            "$apr1$"),
    SensitiveTarget("/web.config",          Severity.HIGH,     "web.config exposed"),
    SensitiveTarget("/server-status",       Severity.HIGH,     "Apache server-status exposed", "Apache Server Status"),
    SensitiveTarget("/server-info",         Severity.MEDIUM,   "Apache server-info exposed"),
    SensitiveTarget("/nginx_status",        Severity.LOW,      "nginx status page exposed"),
    SensitiveTarget("/.well-known/security.txt", Severity.LOW, "security.txt present"),

    # --- Container / cloud ---
    SensitiveTarget("/Dockerfile",          Severity.MEDIUM,   "Dockerfile exposed"),
    SensitiveTarget("/docker-compose.yml",  Severity.MEDIUM,   "docker-compose.yml exposed"),
    SensitiveTarget("/.dockerignore",       Severity.LOW,      ".dockerignore exposed"),
    SensitiveTarget("/latest/meta-data/",   Severity.HIGH,     "AWS EC2 metadata endpoint"),

    # --- Package manifests ---
    SensitiveTarget("/package.json",        Severity.LOW,      "package.json (dep list) exposed"),
    SensitiveTarget("/package-lock.json",   Severity.LOW,      "package-lock.json exposed"),
    SensitiveTarget("/composer.json",       Severity.LOW,      "composer.json exposed"),
    SensitiveTarget("/Gemfile",             Severity.LOW,      "Gemfile (Ruby deps) exposed"),
    SensitiveTarget("/requirements.txt",    Severity.LOW,      "requirements.txt exposed"),
    SensitiveTarget("/yarn.lock",           Severity.LOW,      "yarn.lock exposed"),
    SensitiveTarget("/Makefile",            Severity.LOW,      "Makefile exposed"),

    # --- Spring Boot Actuator endpoints ---
    SensitiveTarget("/actuator",            Severity.HIGH,     "Spring Boot Actuator exposed",   "actuator"),
    SensitiveTarget("/actuator/env",        Severity.CRITICAL, "Spring Actuator env exposed",    "propert"),
    SensitiveTarget("/actuator/health",     Severity.LOW,      "Spring Actuator health exposed", "status"),
    SensitiveTarget("/actuator/beans",      Severity.HIGH,     "Spring Actuator beans exposed",  "bean"),
    SensitiveTarget("/actuator/configprops", Severity.HIGH,    "Spring Actuator config exposed", "prefix"),
    SensitiveTarget("/actuator/mappings",   Severity.MEDIUM,   "Spring Actuator mappings exposed", "dispatcherServlet"),
    SensitiveTarget("/actuator/heapdump",   Severity.CRITICAL, "Spring Actuator heap dump exposed"),
    SensitiveTarget("/actuator/threaddump", Severity.MEDIUM,   "Spring Actuator thread dump exposed"),

    # --- API documentation ---
    SensitiveTarget("/swagger-ui.html",     Severity.MEDIUM,   "Swagger UI exposed",            "swagger"),
    SensitiveTarget("/swagger-ui/",         Severity.MEDIUM,   "Swagger UI exposed",            "swagger"),
    SensitiveTarget("/api-docs",            Severity.MEDIUM,   "API documentation exposed"),
    SensitiveTarget("/v1/api-docs",         Severity.MEDIUM,   "API docs (v1) exposed"),
    SensitiveTarget("/v2/api-docs",         Severity.MEDIUM,   "Swagger API docs (v2) exposed", "swagger"),
    SensitiveTarget("/v3/api-docs",         Severity.MEDIUM,   "OpenAPI docs (v3) exposed",     "openapi"),
    SensitiveTarget("/openapi.json",        Severity.MEDIUM,   "OpenAPI spec exposed",          "openapi"),
    SensitiveTarget("/openapi.yaml",        Severity.MEDIUM,   "OpenAPI spec exposed"),
    SensitiveTarget("/redoc",               Severity.MEDIUM,   "ReDoc API documentation exposed"),

    # --- GraphQL ---
    SensitiveTarget("/graphql",             Severity.MEDIUM,   "GraphQL endpoint exposed"),
    SensitiveTarget("/graphiql",            Severity.HIGH,     "GraphiQL IDE exposed",          "graphiql"),
    SensitiveTarget("/altair",              Severity.HIGH,     "Altair GraphQL client exposed"),
    SensitiveTarget("/playground",          Severity.HIGH,     "GraphQL Playground exposed"),

    # --- CI/CD and DevOps ---
    SensitiveTarget("/jenkins/",            Severity.HIGH,     "Jenkins dashboard accessible"),
    SensitiveTarget("/.github/workflows",   Severity.MEDIUM,   "GitHub Actions workflows exposed"),
    SensitiveTarget("/.gitlab-ci.yml",      Severity.MEDIUM,   "GitLab CI config exposed"),
    SensitiveTarget("/Jenkinsfile",         Severity.MEDIUM,   "Jenkinsfile exposed"),
    SensitiveTarget("/.circleci/config.yml", Severity.MEDIUM,  "CircleCI config exposed"),
    SensitiveTarget("/.travis.yml",         Severity.LOW,      "Travis CI config exposed"),

    # --- Infrastructure / IaC ---
    SensitiveTarget("/terraform.tfstate",   Severity.CRITICAL, "Terraform state file exposed"),
    SensitiveTarget("/terraform.tfstate.backup", Severity.CRITICAL, "Terraform state backup exposed"),
    SensitiveTarget("/.terraform/",         Severity.HIGH,     "Terraform directory exposed"),
    SensitiveTarget("/ansible.cfg",         Severity.MEDIUM,   "Ansible config exposed"),
    SensitiveTarget("/Vagrantfile",         Severity.LOW,      "Vagrantfile exposed"),

    # --- Source maps (expose original source code) ---
    SensitiveTarget("/main.js.map",         Severity.MEDIUM,   "JavaScript source map exposed"),
    SensitiveTarget("/app.js.map",          Severity.MEDIUM,   "JavaScript source map exposed"),
    SensitiveTarget("/bundle.js.map",       Severity.MEDIUM,   "JavaScript source map exposed"),
    SensitiveTarget("/static/js/main.js.map", Severity.MEDIUM, "JavaScript source map exposed"),

    # --- Cloud metadata ---
    SensitiveTarget("/latest/meta-data/iam/security-credentials/", Severity.CRITICAL,
                    "AWS IAM credentials via metadata"),
    SensitiveTarget("/metadata/v1/",        Severity.HIGH,     "Cloud metadata endpoint (DigitalOcean/GCP)"),
    SensitiveTarget("/metadata/instance",   Severity.HIGH,     "Azure metadata endpoint"),

    # --- Monitoring / Observability ---
    SensitiveTarget("/metrics",             Severity.MEDIUM,   "Prometheus metrics exposed"),
    SensitiveTarget("/debug/pprof/",        Severity.HIGH,     "Go pprof profiler exposed",     "pprof"),
    SensitiveTarget("/debug/vars",          Severity.HIGH,     "Go expvar debug info exposed"),
    SensitiveTarget("/_debug",              Severity.MEDIUM,   "Debug endpoint exposed"),
    SensitiveTarget("/trace",               Severity.HIGH,     "Trace endpoint exposed"),
    SensitiveTarget("/health",              Severity.LOW,      "Health check endpoint"),
    SensitiveTarget("/healthz",             Severity.LOW,      "Kubernetes health endpoint"),
    SensitiveTarget("/readyz",              Severity.LOW,      "Kubernetes readiness endpoint"),
]

# 404-indicator words — if these appear in an HTML response, treat as not-found
_NOT_FOUND_WORDS = {"not found", "404", "page not found", "doesn't exist", "no page"}

# File extensions that should NEVER be served as text/html — if the server
# returns HTML for these, it's a catch-all / custom 404, not a real file.
_NON_HTML_EXTENSIONS = {
    ".sql", ".zip", ".tar.gz", ".gz", ".bak", ".7z",
    ".yml", ".yaml", ".json", ".xml", ".properties",
    ".py", ".php", ".rb", ".java", ".cs",
    ".env", ".cfg", ".conf", ".ini", ".toml",
    ".lock", ".txt",
}


class SensitiveFileTester(BaseTester):
    """Discovers sensitive files and directories exposed on the target web server."""

    def __init__(self) -> None:
        super().__init__(name="Sensitive File Discovery")
        self._homepage_bodies: dict[str, str] = {}   # origin → homepage body hash

    def _fetch_homepage_body(self, origin: str) -> str:
        """Fetch and cache the homepage body for SPA catch-all detection."""
        if origin not in self._homepage_bodies:
            try:
                resp = http_utils.get(origin + "/")
                self._homepage_bodies[origin] = resp.text.strip() if resp.status_code == 200 else ""
            except Exception:
                self._homepage_bodies[origin] = ""
        return self._homepage_bodies[origin]

    def run(self, pages: list[CrawledPage]) -> list[Finding]:
        self.findings.clear()
        self._params_tested = 0
        self._homepage_bodies.clear()

        origins: set[str] = set()
        for page in pages:
            p = urlparse(page.url)
            origins.add(f"{p.scheme}://{p.netloc}")

        for origin in origins:
            # Pre-fetch homepage for catch-all detection
            self._fetch_homepage_body(origin)
            for target in SENSITIVE_TARGETS:
                self._probe(origin, target)

        return self.findings

    def _probe(self, origin: str, target: SensitiveTarget) -> None:
        self._count_test()
        url = urljoin(origin.rstrip("/") + "/", target.path.lstrip("/"))
        try:
            resp = http_utils.get(url)
        except Exception:
            return

        if resp.status_code not in (200, 206):
            return

        body = resp.text
        ct   = resp.headers.get("Content-Type", "")

        # Confirm text check
        if target.confirm_text and target.confirm_text.lower() not in body.lower():
            return

        # False-positive guard: HTML response without confirm_text on plain paths
        if not target.confirm_text and "text/html" in ct:
            body_lower = body.lower()
            if any(w in body_lower for w in _NOT_FOUND_WORDS):
                return

        # Content-type mismatch guard: non-HTML files served as HTML are false positives.
        # SKIP this guard when confirm_text already matched — the content is genuine.
        if "text/html" in ct and not target.confirm_text:
            path_lower = target.path.lower()
            basename = path_lower.rsplit("/", 1)[-1]
            if basename.startswith("."):
                return
            if any(path_lower.endswith(ext) for ext in _NON_HTML_EXTENSIONS):
                return

        # SPA catch-all guard: if the response body matches the homepage,
        # the server is just returning its fallback page, not a real file.
        # This runs even when confirm_text matched, because generic confirm
        # strings (e.g. "password", "status") can appear on a fallback page.
        if "text/html" in ct:
            homepage = self._fetch_homepage_body(origin)
            if homepage and body.strip() == homepage:
                return

        snippet = body[:300].replace("\n", " ").strip()
        self._log_finding(Finding(
            vuln_type=VulnType.SENSITIVE_FILE,
            severity=target.severity,
            url=url,
            parameter="(file path)",
            method="GET",
            payload=target.path,
            evidence=f"{target.description} — HTTP {resp.status_code} | {snippet[:250]}",
            remediation=_REMEDIATION,
            extra={"status_code": resp.status_code, "content_type": ct},
        ))
