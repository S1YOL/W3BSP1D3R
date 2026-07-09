from __future__ import annotations
"""
scanner/core.py
----------------
WebVulnScanner — the main orchestrator class.

This is the "conductor" that:
  1. Initialises the HTTP session (rate limiting, User-Agent, auth cookies)
  2. Authenticates to the target if credentials were provided
  3. Runs the crawler to map the attack surface
  4. Dispatches the appropriate testers based on --scan-type
  5. Aggregates all findings into a ScanSummary
  6. Writes all requested output formats (Markdown, HTML, JSON, SARIF, PDF)

Enterprise features integrated:
  - YAML config file support with scan profiles
  - Structured JSON logging with correlation IDs
  - Retry with exponential backoff and adaptive rate limiting
  - Scan scope control (include/exclude URL patterns)
  - Finding deduplication via stable fingerprints
  - Checkpoint/resume for long-running scans
  - Audit trail logging
  - Plugin system for custom testers
  - Enterprise auth (OAuth2, NTLM, API keys)
  - Historical scan database (SQLite)
  - PDF report generation
  - Report diff/comparison against previous scans

Design principle: core.py knows HOW to orchestrate but not HOW to test.
All vulnerability logic lives in testers/. All output logic lives in reporting/.
Adding a new vulnerability type = add a new tester + register it in _TESTERS.
"""

import logging
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from typing import Any, Literal, Optional

from scanner.auth import AuthHandler
from scanner.crawler import Crawler
from scanner.reporting.models import Finding, ScanSummary, Severity, VulnType
from scanner.reporting.json_report import write_json_report
from scanner.reporting.markdown_report import write_markdown_report
from scanner.reporting.html_report import write_html_report
from scanner.reporting.sarif_report import write_sarif_report
from scanner.testers.base import BaseTester, set_scope_patterns
from scanner.testers.cmdi import CmdInjectionTester
from scanner.testers.cookie_security import CookieSecurityTester
from scanner.testers.cors import CORSTester
from scanner.testers.csrf import CSRFTester
from scanner.testers.headers import HeadersTester
from scanner.testers.idor import IDORTester
from scanner.testers.nosql_injection import NoSQLInjectionTester
from scanner.testers.open_redirect import OpenRedirectTester
from scanner.testers.path_traversal import PathTraversalTester
from scanner.testers.sensitive_files import SensitiveFileTester
from scanner.testers.sqli import SQLiTester
from scanner.testers.ssl_tls import SSLTLSTester
from scanner.testers.ssti import SSTITester
from scanner.testers.subdomain import SubdomainTester
from scanner.testers.waf import WAFTester
from scanner.testers.xss import XSSTester
from scanner.testers.cve import CveTester
from scanner.testers.dir_discovery import DirDiscoveryTester
from scanner.testers.http_methods import HTTPMethodTester
from scanner.testers.tech_fingerprint import TechFingerprintTester
from scanner.testers.xxe import XXETester
from scanner.testers.jwt_test import JWTTester
from scanner.testers.info_disclosure import InfoDisclosureTester
from scanner.testers.rate_limit import RateLimitTester
from scanner.testers.clickjacking import ClickjackingTester
from scanner.testers.dom_xss import DOMXSSTester
from scanner.utils import http as http_utils
from scanner.utils.display import (
    console,
    make_progress,
    print_banner,
    print_error,
    print_finding,
    print_info,
    print_phase,
    print_scan_start,
    print_success,
    print_summary,
    print_warning,
    print_status,
    RateLimitDashboard,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Scan type → tester mapping
# ---------------------------------------------------------------------------

ScanType = Literal["full", "passive", "sqli", "xss", "csrf",
                   "headers", "files", "traversal", "redirect", "cmdi",
                   "cve", "idor", "waf", "ssti", "cors", "ssl",
                   "cookies", "nosqli", "subdomains",
                   "dirs", "methods", "fingerprint",
                   "xxe", "jwt", "info", "ratelimit", "clickjack", "domxss"]

_TESTER_MAP: dict[str, type[BaseTester]] = {
    "sqli":        SQLiTester,
    "xss":         XSSTester,
    "csrf":        CSRFTester,
    "headers":     HeadersTester,
    "files":       SensitiveFileTester,
    "traversal":   PathTraversalTester,
    "redirect":    OpenRedirectTester,
    "cmdi":        CmdInjectionTester,
    "cve":         CveTester,
    "idor":        IDORTester,
    "waf":         WAFTester,
    "ssti":        SSTITester,
    "cors":        CORSTester,
    "ssl":         SSLTLSTester,
    "cookies":     CookieSecurityTester,
    "nosqli":      NoSQLInjectionTester,
    "subdomains":  SubdomainTester,
    "dirs":        DirDiscoveryTester,
    "methods":     HTTPMethodTester,
    "fingerprint": TechFingerprintTester,
    "xxe":         XXETester,
    "jwt":         JWTTester,
    "info":        InfoDisclosureTester,
    "ratelimit":   RateLimitTester,
    "clickjack":   ClickjackingTester,
}


class WebVulnScanner:
    """
    Main scanner class — instantiate once, call scan() to execute.

    Supports both programmatic construction and config-file-driven setup.
    All enterprise features (audit, checkpoint, plugins, database) are
    activated via the config parameter or individual flags.
    """

    VERSION = "3.0.0-beta"

    def __init__(
        self,
        url: str,
        scan_type: ScanType = "full",
        login_user: str | None = None,
        login_pass: str | None = None,
        output: str = "scan_report",
        max_pages: int = 50,
        delay: float = 0.5,
        timeout: int = 10,
        verify_ssl: bool = True,
        threads: int = 4,
        vt_api_key: str | None = None,
        vt_delay: float = 15.0,
        nvd_api_key: str | None = None,
        proxy: str | None = None,
        auth_token: str | None = None,
        fail_on: str | None = None,
        # Enterprise parameters
        config: Any | None = None,  # ScanConfig object
        scan_id: str | None = None,
    ) -> None:
        # Generate scan ID for correlation
        self.scan_id = scan_id or uuid.uuid4().hex[:12]

        # If a ScanConfig is provided, use its values as defaults
        if config is not None:
            self._init_from_config(config)
        else:
            self.url        = url.rstrip("/")
            self.scan_type  = scan_type
            self.login_user = login_user
            self.login_pass = login_pass
            self.output     = output
            self.max_pages  = max_pages
            self.threads    = max(1, threads)
            self.vt_api_key  = vt_api_key
            self.vt_delay    = vt_delay
            self.nvd_api_key = nvd_api_key
            self.fail_on     = fail_on
            self.output_formats = ["html", "md", "json", "sarif"]
            self._config = None

            # Per-scan HTTP client (isolated from any other concurrent scan)
            self._http = http_utils.new_client(
                delay=delay,
                timeout=timeout,
                verify_ssl=verify_ssl,
                proxy=proxy,
                auth_token=auth_token,
            )

        # SSRF guard: only allow redirects to the target origin
        from urllib.parse import urlparse as _urlparse
        _parsed = _urlparse(self.url)
        _target_origin = f"{_parsed.scheme}://{_parsed.netloc}"
        self._http.set_allowed_origins({_target_origin})

        # Enterprise components — initialised lazily
        self._audit = None
        self._checkpoint = None
        self._plugin_manager = None
        self._database = None
        self._enterprise_auth = None
        self._compare_with = None
        self._webhooks = None
        self._dashboard_enabled = False
        self._resume = bool(getattr(config, "resume", False)) if config else False
        self._resume_state = None
        self._interact = bool(getattr(config, "interact", False)) if config else False
        # Interaction-driven crawling needs a browser, so it implies rendering.
        self._render = (bool(getattr(config, "render", False)) if config else False) or self._interact
        self._api_endpoints: list = []   # REST/JSON endpoints found by crawler (Phase D)

        # For checkpoint/resume to work across separate runs, the checkpoint id
        # must be stable for the same target + scan type (a random uuid each run
        # could never be found again).
        if config is not None and config.checkpoint.enabled and scan_id is None:
            import hashlib as _hashlib
            self.scan_id = _hashlib.sha1(
                f"{self.url}|{self.scan_type}".encode()
            ).hexdigest()[:12]

        if config is not None:
            self._init_enterprise(config)

        # Will be populated during scan()
        self.summary: ScanSummary | None = None

    def _init_from_config(self, config) -> None:
        """Initialize scanner parameters from a ScanConfig object."""
        self._config = config
        self.url = config.url.rstrip("/")
        self.scan_type = config.scan_type
        self.login_user = config.auth.username
        self.login_pass = config.auth.password
        self.output = config.output
        self.max_pages = config.max_pages
        self.threads = max(1, config.threads)
        self.vt_api_key = config.vt_api_key
        self.vt_delay = config.vt_delay
        self.nvd_api_key = config.nvd_api_key
        self.fail_on = config.fail_on
        self.output_formats = config.output_formats
        self._compare_with = config.compare_with

        # Per-scan HTTP client (isolated from any other concurrent scan)
        self._http = http_utils.new_client(
            delay=config.delay,
            timeout=config.timeout,
            verify_ssl=config.verify_ssl,
            proxy=config.proxy,
            auth_token=config.auth.token,
            max_retries=config.rate_limit.max_retries,
            backoff_factor=config.rate_limit.backoff_factor,
            adaptive_rate_limit=config.rate_limit.adaptive,
            retry_on_status=tuple(config.rate_limit.retry_on_status),
        )

        # Set scope patterns
        set_scope_patterns(
            include=config.scope.include,
            exclude=config.scope.exclude,
        )

    def _init_enterprise(self, config) -> None:
        """Initialize enterprise components from config."""
        # Audit logging
        if config.audit.enabled:
            from scanner.audit import AuditLogger
            self._audit = AuditLogger(
                log_file=config.audit.log_file,
                enabled=True,
            )

        # Checkpoint/resume
        if config.checkpoint.enabled:
            from scanner.checkpoint import CheckpointManager
            self._checkpoint = CheckpointManager(
                scan_id=self.scan_id,
                directory=config.checkpoint.directory,
                enabled=True,
            )
            if self._resume and self._checkpoint.has_checkpoint():
                self._resume_state = self._checkpoint.load()

        # Plugin system
        if config.plugins.enabled:
            from scanner.plugins import PluginManager
            self._plugin_manager = PluginManager(
                directories=config.plugins.directories,
                enabled=True,
            )

        # Database
        if config.database.enabled:
            from scanner.db import ScanDatabase
            self._database = ScanDatabase(
                path=config.database.path,
                enabled=True,
            )

        # Enterprise auth
        if config.auth.auth_type not in ("none", "form"):
            from scanner.auth_enterprise import EnterpriseAuth
            self._enterprise_auth = EnterpriseAuth(config.auth)

        # Webhooks
        if hasattr(config, "webhooks") and config.webhooks.enabled:
            from scanner.webhooks import WebhookNotifier
            self._webhooks = WebhookNotifier(config.webhooks)

        # Rate limit dashboard
        self._dashboard_enabled = getattr(config, "dashboard", False)

    # ------------------------------------------------------------------
    # Main entry point
    # ------------------------------------------------------------------

    def scan(self) -> ScanSummary:
        """
        Execute the full scan pipeline and return the completed ScanSummary.

        Pipeline:
          audit_start → authenticate → crawl → test → virustotal →
          finalise → report → diff → audit_complete → database_save
        """
        print_banner(self.VERSION)

        # Bind this scan's isolated HTTP client to the current thread so the
        # crawler and (main-thread) auth use it. Worker threads re-bind it in
        # _run_testers_concurrent. This is what keeps concurrent scans isolated.
        http_utils.set_current_client(self._http)

        started_at = datetime.now(timezone.utc).isoformat()
        scan_start_time = time.monotonic()
        authenticated = False

        # ---- Audit: record scan start ------------------------------------
        if self._audit:
            self._audit.log_scan_start(
                scan_id=self.scan_id,
                target=self.url,
                scan_type=self.scan_type,
                config={
                    "threads": self.threads,
                    "max_pages": self.max_pages,
                    "output_formats": self.output_formats,
                },
            )

        # ---- Step 1: Authenticate ----------------------------------------
        if self._enterprise_auth:
            print_phase("Enterprise Authentication")
            authenticated = self._enterprise_auth.authenticate()
            if not authenticated:
                print_warning("Enterprise auth failed — continuing unauthenticated.")
            else:
                print_success("Enterprise authentication successful")
            if self._audit:
                auth_type = self._config.auth.auth_type if self._config else "enterprise"
                self._audit.log_auth_attempt(
                    scan_id=self.scan_id,
                    target=self.url,
                    auth_type=auth_type,
                    success=authenticated,
                )
        elif self.login_user and self.login_pass:
            print_phase("Authentication")
            auth = AuthHandler(self.url, self.login_user, self.login_pass)
            authenticated = auth.login()
            if not authenticated:
                print_warning(
                    "Continuing as unauthenticated — some pages may be inaccessible."
                )
            if self._audit:
                self._audit.log_auth_attempt(
                    scan_id=self.scan_id,
                    target=self.url,
                    auth_type="form",
                    success=authenticated,
                    username=self.login_user,
                )
        else:
            print_info("No credentials provided — running unauthenticated scan.")

        print_scan_start(self.url, self.scan_type, authenticated)

        # Initialise the summary object (findings get added as testers run)
        self.summary = ScanSummary(
            target_url=self.url,
            scan_type=self.scan_type,
            started_at=started_at,
        )

        # ---- Start rate limit dashboard (if enabled) ----------------------
        dashboard = None
        if self._dashboard_enabled:
            dashboard = RateLimitDashboard()
            dashboard.start()

        # ---- Step 2: Crawl -----------------------------------------------
        print_phase("Crawling — Mapping Attack Surface")
        pages = self._crawl()
        self.summary.pages_crawled = len(pages)
        self.summary.forms_found   = sum(len(p.forms) for p in pages)
        _api_note = (
            f", {len(self._api_endpoints)} API endpoint(s)"
            if self._api_endpoints else ""
        )
        print_success(
            f"Crawl complete: {self.summary.pages_crawled} pages, "
            f"{self.summary.forms_found} forms discovered{_api_note}."
        )

        # A JSON/API-first target can yield zero HTML pages but still expose
        # injectable API endpoints — only bail out when there's nothing at all.
        if not pages and not self._api_endpoints:
            print_error("No pages were crawled. Check the target URL and connectivity.")
            self.summary.finished_at = datetime.now(timezone.utc).isoformat()
            return self.summary

        # Save crawl checkpoint
        if self._checkpoint:
            self._checkpoint.save_crawl_state(
                visited_urls=[p.url for p in pages],
                queue_urls=[],
                pages_data=[{"url": p.url, "forms": len(p.forms)} for p in pages],
            )

        # ---- Step 3: Run testers (concurrent) ---------------------------
        testers = self._build_testers()

        # Hand discovered REST/JSON API endpoints to testers that fuzz them
        # (Phase D). Testers that only work on HTML pages ignore these.
        for _t in testers:
            _t.set_api_endpoints(self._api_endpoints)

        # Resume: preload prior findings and skip already-completed testers.
        if self._resume_state:
            completed = set(self._resume_state.get("completed_testers", []))
            restored = 0
            for fd in self._resume_state.get("findings", []):
                try:
                    if self.summary.add_finding(Finding.from_dict(fd)):
                        restored += 1
                except Exception:
                    continue
            self.summary.params_tested = self._resume_state.get("params_tested", 0)
            if completed:
                before = len(testers)
                testers = [t for t in testers if t.name not in completed]
                print_success(
                    f"Resuming scan {self.scan_id}: restored {restored} finding(s), "
                    f"skipping {before - len(testers)} completed module(s)."
                )

        print_phase(f"Testing — {len(testers)} modules, up to {self.threads} concurrent")
        if dashboard:
            dashboard.set_info("Phase", "Testing")
            dashboard.set_info("Modules", str(len(testers)))
        self._run_testers_concurrent(testers, pages)

        # ---- Step 4: VirusTotal check ------------------------------------
        if self.vt_api_key:
            print_phase("VirusTotal Threat Intelligence")
            self._run_virustotal(pages)
        else:
            print_info("Skipping VirusTotal (no --vt-api-key provided)")

        # ---- Step 5: Finalise summary ------------------------------------
        self.summary.finished_at = datetime.now(timezone.utc).isoformat()
        scan_duration = time.monotonic() - scan_start_time

        # Show request metrics
        req_metrics = http_utils.get_metrics()
        if req_metrics["total_requests"] > 0:
            print_info(
                f"HTTP metrics: {req_metrics['total_requests']} requests, "
                f"{req_metrics['retried']} retried, "
                f"{req_metrics['rate_limited']} rate-limited, "
                f"avg {req_metrics['avg_response_time']:.2f}s"
            )

        print_summary(self.summary)

        # ---- Step 6: Write reports ---------------------------------------
        print_phase("Generating Reports")
        self._write_reports()

        # ---- Step 7: Diff comparison (if configured) ---------------------
        if self._compare_with:
            self._run_diff_comparison()

        # ---- Step 8: Audit + Database ------------------------------------
        if self._audit:
            self._audit.log_scan_complete(
                scan_id=self.scan_id,
                target=self.url,
                duration_seconds=scan_duration,
                findings_count=self.summary.total_findings,
                severity_breakdown={
                    "critical": self.summary.critical_count,
                    "high": self.summary.high_count,
                    "medium": self.summary.medium_count,
                    "low": self.summary.low_count,
                },
            )

        if self._database:
            self._database.save_scan(
                scan_id=self.scan_id,
                summary=self.summary,
                config={"scan_type": self.scan_type, "threads": self.threads},
                metrics=req_metrics,
            )
            print_info(f"Scan saved to database (ID: {self.scan_id})")

        # ---- Stop dashboard ------------------------------------------------
        if dashboard:
            dashboard.stop()

        # ---- Step 9: Webhook notifications --------------------------------
        if self._webhooks and self.summary:
            try:
                self._webhooks.notify_scan_complete(self.summary, self.scan_id)
                print_success("Webhook notifications sent")
            except Exception as exc:
                print_warning(f"Webhook notification failed: {exc}")

        # Clear checkpoint on successful completion
        if self._checkpoint:
            self._checkpoint.clear()

        return self.summary

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _crawl(self) -> list:
        """Execute the crawler with a rich progress display."""
        crawler = Crawler(base_url=self.url, max_pages=self.max_pages,
                          render=self._render, interact=self._interact)

        with make_progress() as progress:
            task = progress.add_task(
                "Crawling site…",
                total=self.max_pages,
                status="",
            )

            def _update_progress():
                while not progress.finished:
                    visited = len(crawler._visited)
                    progress.update(
                        task,
                        completed=visited,
                        status=f"{visited} pages visited",
                    )
                    time.sleep(0.3)

            monitor = threading.Thread(target=_update_progress, daemon=True)
            monitor.start()

            pages = crawler.crawl()

            progress.update(task, completed=self.max_pages, status="Done")

        # Stash REST/JSON API endpoints discovered during the crawl (Phase D).
        self._api_endpoints = crawler.api_endpoints
        return pages

    def _run_testers_concurrent(self, testers: list[BaseTester], pages: list) -> None:
        """
        Run all testers using a thread pool. Each tester operates on the same
        list of crawled pages independently. Findings are collected thread-safely
        and added to the summary as they arrive.
        """
        _lock = threading.Lock()
        completed_testers: list[str] = []

        # Capture this scan's client + scope so each worker thread rebinds them
        # (ContextVars do not propagate into ThreadPoolExecutor workers).
        _client = self._http
        from scanner.testers.base import get_scope_patterns, set_scope_patterns
        _scope = get_scope_patterns()

        def _run_one(tester: BaseTester):
            http_utils.set_current_client(_client)
            set_scope_patterns(*_scope)
            findings = tester.run(pages)
            with _lock:
                self.summary.params_tested += tester.params_tested
                for f in findings:
                    added = self.summary.add_finding(f)
                    if added:
                        print_finding(f)
                        # Audit each finding
                        if self._audit:
                            self._audit.log_finding(
                                scan_id=self.scan_id,
                                vuln_type=f.vuln_type,
                                severity=f.severity,
                                url=f.url,
                                parameter=f.parameter,
                                fingerprint=f.fingerprint,
                            )

                completed_testers.append(tester.name)
                print_status(f"{tester.name} complete — {len(findings)} finding(s)")

                # Save checkpoint after each tester completes
                if self._checkpoint:
                    self._checkpoint.save_tester_progress(
                        completed_testers=list(completed_testers),
                        findings=[f.to_dict() for f in self.summary.findings],
                        params_tested=self.summary.params_tested,
                    )

        with ThreadPoolExecutor(max_workers=self.threads) as pool:
            futures = {pool.submit(_run_one, t): t for t in testers}
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as exc:
                    tester = futures[future]
                    logger.error("Tester %s error: %s", tester.name, exc)
                    if self._audit:
                        self._audit.log_error(
                            scan_id=self.scan_id,
                            error_type="tester_failure",
                            message=str(exc),
                            context={"tester": tester.name},
                        )

    def _run_virustotal(self, pages: list) -> None:
        """Check the target domain and any suspicious file URLs via VirusTotal."""
        from scanner.virustotal import scan_target  # lazy — only when VT is used

        crawled_urls = [p.url for p in pages]

        try:
            flagged = scan_target(
                base_url=self.url,
                crawled_urls=crawled_urls,
                api_key=self.vt_api_key,
                request_delay=self.vt_delay,
            )
        except Exception as exc:
            print_warning(f"VirusTotal check failed: {exc}")
            return

        for result in flagged:
            resource      = result.get("resource", "?")
            resource_type = result.get("resource_type", "?")
            malicious     = result.get("malicious", 0)
            suspicious    = result.get("suspicious", 0)
            total         = result.get("total_engines", 0)
            categories    = result.get("categories", {})

            severity = Severity.CRITICAL if malicious > 2 else (
                Severity.HIGH if malicious > 0 else Severity.MEDIUM
            )
            finding = Finding(
                vuln_type=VulnType.VIRUSTOTAL,
                severity=severity,
                url=resource if resource_type == "url" else self.url,
                parameter=f"{resource_type}: {resource}",
                method="GET",
                payload="(VirusTotal API lookup — no payload sent to target)",
                evidence=(
                    f"VirusTotal: {malicious} malicious, {suspicious} suspicious "
                    f"out of {total} engines. "
                    + (f"Categories: {', '.join(categories.values())}" if categories else "")
                ),
                remediation=(
                    "Investigate the flagged resource at https://www.virustotal.com. "
                    "If the domain/URL is legitimately yours, consider submitting a "
                    "false-positive report to VirusTotal. If confirmed malicious, "
                    "immediately isolate and remediate the affected server."
                ),
                extra=result,
            )
            self.summary.add_finding(finding)
            print_finding(finding)

        if not flagged:
            print_success("VirusTotal: no threats detected for this target")

    def _build_testers(self) -> list[BaseTester]:
        """
        Instantiate the appropriate testers based on --scan-type.

        "full"    = all built-in testers + any loaded plugins.
        "passive" = headers + sensitive files + CVE lookup (no attack payloads).
        Any other value = only the named tester.
        """
        def _make(cls: type[BaseTester]) -> BaseTester:
            if cls is CveTester:
                return CveTester(nvd_api_key=self.nvd_api_key)
            return cls()

        # Load plugins if configured
        plugin_testers: dict[str, type[BaseTester]] = {}
        if self._plugin_manager:
            plugin_testers = self._plugin_manager.discover()
            if plugin_testers:
                print_info(f"Loaded {len(plugin_testers)} plugin tester(s)")
            if self._plugin_manager.errors:
                for err in self._plugin_manager.errors:
                    print_warning(f"Plugin error: {err['file']}: {err['error']}")

        # Merge plugin testers into the full map
        all_testers = dict(_TESTER_MAP)
        all_testers.update(plugin_testers)

        if self.scan_type == "domxss":
            return [DOMXSSTester()]

        if self.scan_type == "full":
            testers = [_make(cls) for cls in all_testers.values()]
            # DOM XSS needs a headless browser — only run it when rendering is
            # enabled (otherwise it would launch a browser on every full scan).
            if self._render:
                testers.append(DOMXSSTester())
            return testers

        if self.scan_type == "passive":
            passive = [
                HeadersTester(), SensitiveFileTester(), _make(CveTester),
                WAFTester(), CORSTester(), SSLTLSTester(),
                CookieSecurityTester(), SubdomainTester(),
                DirDiscoveryTester(), HTTPMethodTester(),
                TechFingerprintTester(), JWTTester(),
                InfoDisclosureTester(), ClickjackingTester(),
            ]
            # Add any passive-safe plugins
            return passive

        # Check both built-in and plugin testers
        tester_cls = all_testers.get(self.scan_type)
        if not tester_cls:
            print_error(
                f"Unknown scan type '{self.scan_type}'. "
                f"Valid options: full, passive, {', '.join(all_testers.keys())}"
            )
            return []

        return [_make(tester_cls)]

    def _run_diff_comparison(self) -> None:
        """Compare current results against a baseline scan."""
        if not self._compare_with or not self.summary:
            return

        try:
            from scanner.reporting.diff_report import (
                compare_with_file,
                write_diff_report_md,
                write_diff_report_json,
            )

            print_phase("Scan Comparison")
            diff = compare_with_file(self.summary, self._compare_with)

            # Print summary
            if diff.total_new > 0:
                print_warning(f"{diff.total_new} NEW finding(s) since baseline")
            if diff.total_fixed > 0:
                print_success(f"{diff.total_fixed} finding(s) FIXED since baseline")
            print_info(f"{diff.total_unchanged} finding(s) unchanged")

            # Write diff reports
            base = self.output
            diff_md = write_diff_report_md(diff, f"{base}_diff.md")
            diff_json = write_diff_report_json(diff, f"{base}_diff.json")
            console.print(f"  [red]→[/red] {diff_md}")
            console.print(f"  [red]→[/red] {diff_json}")

        except FileNotFoundError:
            print_warning(f"Baseline report not found: {self._compare_with}")
        except Exception as exc:
            print_warning(f"Diff comparison failed: {exc}")
            logger.exception("Diff comparison error")

    def should_fail(self) -> bool:
        """
        Check if the scan should return a non-zero exit code based on --fail-on.

        Used for CI/CD pipeline integration — fail the build if findings
        meet or exceed the configured severity threshold.
        """
        if not self.fail_on or not self.summary:
            return False

        threshold = self.fail_on.lower()
        if threshold == "critical" and self.summary.critical_count > 0:
            return True
        if threshold == "high" and (self.summary.critical_count + self.summary.high_count) > 0:
            return True
        if threshold == "medium" and (
            self.summary.critical_count + self.summary.high_count + self.summary.medium_count
        ) > 0:
            return True
        if threshold == "low" and self.summary.total_findings > 0:
            return True
        return False

    def _write_reports(self) -> None:
        """Write all configured output formats."""
        if not self.summary:
            return

        base = self.output
        reports = []
        formats = self.output_formats

        try:
            if "md" in formats:
                reports.append(write_markdown_report(self.summary, f"{base}.md"))
            if "html" in formats:
                reports.append(write_html_report(self.summary, f"{base}.html"))
            if "json" in formats:
                reports.append(write_json_report(self.summary, f"{base}.json"))
            if "sarif" in formats:
                reports.append(write_sarif_report(self.summary, f"{base}.sarif"))
            if "pdf" in formats:
                try:
                    from scanner.reporting.pdf_report import write_pdf_report
                    reports.append(write_pdf_report(self.summary, f"{base}.pdf"))
                except ImportError:
                    print_warning(
                        "PDF generation requires fpdf2. "
                        "Install with: pip install fpdf2"
                    )
        except Exception as exc:
            print_error(f"Report generation failed: {exc}")
            logger.exception("Report generation error")
            return

        console.print()
        console.print("[bold white]Reports written:[/bold white]")
        for rpt in reports:
            console.print(f"  [red]→[/red] {rpt}")
        console.print()
