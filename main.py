#!/usr/bin/env python3
from __future__ import annotations
"""
main.py — CLI entry point for W3BSP1D3R.

Usage:
  python main.py --url http://localhost/dvwa --login-user admin --login-pass password
  python main.py --url http://localhost:3000 --scan-type xss --output reports/juice_shop
  python main.py --config w3bsp1d3r.yaml --profile thorough
  python main.py --api-server --api-port 8888

Run `python main.py --help` for full usage.

by S1YOL.

⚠️  LEGAL WARNING ⚠️
  I AM NOT RESPONSIBLE FOR ANYONE USING THIS APP.
  Scanning without authorization is a FEDERAL CRIME under the Computer Fraud
  and Abuse Act (CFAA, 18 U.S.C. § 1030). Only scan systems you own or have
  explicit written permission to test.
"""

import argparse
import logging
import os
import platform
import sys
from pathlib import Path

from scanner.core import WebVulnScanner


# ---------------------------------------------------------------------------
# Logging configuration — controlled by --verbose, --log-format, --log-file
# ---------------------------------------------------------------------------

def _configure_logging(
    verbose: bool,
    log_format: str = "text",
    log_file: str | None = None,
    quiet: bool = False,
) -> None:
    """
    Set up the logging system.

    Supports two modes:
      - "text": Human-readable output (default)
      - "json": Structured JSON lines for SIEM ingestion

    Levels: verbose → DEBUG, quiet → ERROR, otherwise WARNING.
    """
    from scanner.utils.logging_config import configure_logging

    level = "DEBUG" if verbose else ("ERROR" if quiet else "WARNING")
    configure_logging(
        level=level,
        fmt=log_format,
        log_file=log_file,
        include_ids=(log_format == "json" or verbose),
    )


# ---------------------------------------------------------------------------
# CLI argument parser
# ---------------------------------------------------------------------------

def _detect_platform() -> str:
    """Detect the current OS platform for help text and diagnostics."""
    system = platform.system().lower()
    if system == "windows":
        return "windows"
    elif system == "darwin":
        return "macos"
    return "linux"


def _build_examples(plat: str) -> str:
    """Build OS-appropriate example commands for --help epilog."""
    if plat == "windows":
        return """
examples:
  # Full authenticated scan against DVWA
  python main.py --url http://localhost/dvwa --login-user admin --login-pass password --scan-type full --output reports\\dvwa_scan

  # Use a config file with a scan profile
  python main.py --config w3bsp1d3r.yaml --profile thorough

  # SQLi-only scan
  python main.py --url http://localhost/dvwa --scan-type sqli

  # Structured JSON logging for SIEM
  python main.py --url http://localhost/dvwa --log-format json --log-file scan.log

  # Compare with a previous scan
  python main.py --url http://localhost/dvwa --compare-with previous_scan.json

  # Start the REST API server
  python main.py --api-server --api-port 8888

  # CI/CD pipeline — fail build on High+ findings
  python main.py --url http://localhost/dvwa --fail-on high

platform:
  OS:     Windows
  Venv:   venv\\Scripts\\activate  (cmd)
          .\\venv\\Scripts\\Activate.ps1  (PowerShell)
"""
    else:
        return f"""
examples:
  # Full authenticated scan against DVWA
  python main.py --url http://localhost/dvwa \\
                 --login-user admin --login-pass password \\
                 --scan-type full --output reports/dvwa_scan

  # Use a config file with a scan profile
  python main.py --config w3bsp1d3r.yaml --profile thorough

  # SQLi-only scan
  python main.py --url http://localhost/dvwa --scan-type sqli

  # Structured JSON logging for SIEM
  python main.py --url http://localhost/dvwa --log-format json --log-file scan.log

  # Compare with a previous scan
  python main.py --url http://localhost/dvwa --compare-with previous_scan.json

  # Start the REST API server
  python main.py --api-server --api-port 8888

  # CI/CD pipeline — fail build on High+ findings
  python main.py --url http://localhost/dvwa --fail-on high

platform:
  OS:     {'macOS (Darwin)' if plat == 'macos' else 'Linux'}
  Shell:  {'zsh / bash' if plat == 'macos' else 'bash / zsh'}
  Venv:   source venv/bin/activate
  Note:   The scanner sends BOTH Unix and Windows attack payloads to the
          target regardless of which OS you run the scanner on.
"""


def _build_parser() -> argparse.ArgumentParser:
    plat = _detect_platform()

    parser = argparse.ArgumentParser(
        prog="w3bsp1d3r",
        description=(
            "W3BSP1D3R — Enterprise Web Vulnerability Scanner by S1YOL\n"
            "Tests for SQLi, XSS, CSRF, CMDi, SSTI, NoSQLi, Path Traversal,\n"
            "Open Redirect, IDOR, CORS, SSL/TLS, Cookie Security, Sensitive Files,\n"
            "Security Headers, WAF Detection, Subdomain Enumeration, and CVEs.\n\n"
            f"Running on: {platform.system()} {platform.release()} "
            f"({platform.machine()})\n\n"
            "The author assumes no responsibility or liability for any misuse,\n"
            "damage, or legal consequences arising from the use of this software.\n"
            "Only scan systems you have explicit written authorisation to test."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=_build_examples(plat),
    )

    # Required (unless --config or --api-server is used)
    parser.add_argument(
        "--url",
        default=None,
        metavar="URL",
        help="Target base URL (e.g. http://localhost/dvwa)",
    )

    # ---- Configuration file ----
    config_group = parser.add_argument_group("configuration")
    config_group.add_argument(
        "--config",
        default=None,
        metavar="FILE",
        help="YAML configuration file (e.g. w3bsp1d3r.yaml)",
    )
    config_group.add_argument(
        "--profile",
        default=None,
        choices=["quick", "standard", "thorough", "stealth"],
        metavar="PROFILE",
        help="Scan profile: quick | standard | thorough | stealth",
    )

    # Authentication
    auth_group = parser.add_argument_group("authentication")
    auth_group.add_argument(
        "--login-user",
        metavar="USERNAME",
        default=None,
        help="Login username for authenticated scanning",
    )
    auth_group.add_argument(
        "--login-pass",
        metavar="PASSWORD",
        default=None,
        help="Login password for authenticated scanning",
    )

    # Scan configuration
    scan_group = parser.add_argument_group("scan configuration")
    scan_group.add_argument(
        "--scan-type",
        choices=["full", "passive", "sqli", "xss", "csrf",
                 "headers", "files", "traversal", "redirect", "cmdi",
                 "cve", "idor", "waf", "ssti", "cors", "ssl",
                 "cookies", "nosqli", "subdomains",
                 "dirs", "methods", "fingerprint",
                 "xxe", "jwt", "info", "ratelimit", "clickjack", "domxss"],
        default=None,
        metavar="TYPE",
        help=(
            "Scan type (default: full). "
            "full=all | passive=headers+files+cve+waf+cors+ssl+cookies+subdomains "
            "(no attack payloads) | "
            "sqli | xss | csrf | headers | files | traversal | redirect | cmdi | "
            "cve | idor | waf | ssti | cors | ssl | cookies | nosqli | subdomains"
        ),
    )
    scan_group.add_argument(
        "--threads",
        type=int,
        default=None,
        metavar="N",
        help="Number of concurrent tester threads (default: 4)",
    )
    scan_group.add_argument(
        "--max-pages",
        type=int,
        default=None,
        metavar="N",
        help="Maximum pages to crawl (default: 50)",
    )
    scan_group.add_argument(
        "--delay",
        type=float,
        default=None,
        metavar="SECS",
        help="Delay between requests in seconds (default: 0.5)",
    )
    scan_group.add_argument(
        "--timeout",
        type=int,
        default=None,
        metavar="SECS",
        help="Per-request timeout in seconds (default: 10)",
    )
    scan_group.add_argument(
        "--no-verify-ssl",
        action="store_true",
        default=False,
        help="Disable TLS certificate verification (use for self-signed certs in labs)",
    )
    scan_group.add_argument(
        "--render",
        action="store_true",
        default=False,
        help="Render pages in a headless browser to crawl JavaScript/SPA content "
             "and enable DOM-XSS testing (requires: pip install playwright && "
             "playwright install chromium)",
    )

    # Scope control
    scope_group = parser.add_argument_group("scope control")
    scope_group.add_argument(
        "--include",
        nargs="*",
        default=None,
        metavar="PATTERN",
        help="URL patterns to include (fnmatch globs, e.g. '*/admin/*')",
    )
    scope_group.add_argument(
        "--exclude",
        nargs="*",
        default=None,
        metavar="PATTERN",
        help="URL patterns to exclude (fnmatch globs, e.g. '*/logout*')",
    )

    # Output
    out_group = parser.add_argument_group("output")
    out_group.add_argument(
        "--output",
        default=None,
        metavar="FILENAME",
        help=(
            "Base filename for reports, without extension "
            "(default: scan_report)."
        ),
    )
    out_group.add_argument(
        "--formats",
        nargs="*",
        default=None,
        choices=["html", "md", "json", "sarif", "pdf"],
        metavar="FMT",
        help="Report formats to generate (default: html md json sarif)",
    )
    out_group.add_argument(
        "--verbose",
        action="store_true",
        default=False,
        help="Enable verbose logging (shows all HTTP requests and debug info)",
    )
    out_group.add_argument(
        "--quiet",
        action="store_true",
        default=False,
        help="Suppress banner/progress/status output (findings, warnings, and "
             "summary still shown). Ideal for CI/CD pipelines.",
    )

    # Logging
    log_group = parser.add_argument_group("logging")
    log_group.add_argument(
        "--log-format",
        choices=["text", "json"],
        default="text",
        metavar="FMT",
        help="Log output format: text (default) or json (for SIEM integration)",
    )
    log_group.add_argument(
        "--log-file",
        default=None,
        metavar="FILE",
        help="Write logs to file in addition to stderr",
    )

    # VirusTotal
    vt_group = parser.add_argument_group("virustotal")
    vt_group.add_argument(
        "--vt-api-key",
        default=None,
        metavar="KEY",
        help="VirusTotal API key (or set W3BSP1D3R_VT_API_KEY env var)",
    )
    vt_group.add_argument(
        "--vt-delay",
        type=float,
        default=None,
        metavar="SECS",
        help="Delay between VirusTotal API requests (default: 15)",
    )

    # NVD / CVE
    nvd_group = parser.add_argument_group("nvd / cve lookup")
    nvd_group.add_argument(
        "--nvd-api-key",
        default=None,
        metavar="KEY",
        help="NIST NVD API key (or set W3BSP1D3R_NVD_API_KEY env var)",
    )

    # Proxy
    proxy_group = parser.add_argument_group("proxy")
    proxy_group.add_argument(
        "--proxy",
        default=None,
        metavar="URL",
        help="HTTP/HTTPS/SOCKS5 proxy (e.g. http://127.0.0.1:8080 for Burp Suite)",
    )

    # Token-based authentication
    token_group = parser.add_argument_group("token authentication")
    token_group.add_argument(
        "--auth-token",
        default=None,
        metavar="TOKEN",
        help="Bearer/JWT token for token-based authentication",
    )

    # Enterprise auth
    enterprise_auth = parser.add_argument_group("enterprise authentication")
    enterprise_auth.add_argument(
        "--auth-type",
        choices=["form", "bearer", "oauth2", "ntlm", "apikey"],
        default=None,
        metavar="TYPE",
        help="Authentication type for enterprise targets",
    )
    enterprise_auth.add_argument(
        "--oauth2-token-url",
        default=None,
        metavar="URL",
        help="OAuth2 token endpoint URL",
    )
    enterprise_auth.add_argument(
        "--oauth2-client-id",
        default=None,
        metavar="ID",
        help="OAuth2 client ID",
    )
    enterprise_auth.add_argument(
        "--oauth2-client-secret",
        default=None,
        metavar="SECRET",
        help="OAuth2 client secret",
    )
    enterprise_auth.add_argument(
        "--oauth2-scope",
        default=None,
        metavar="SCOPE",
        help="OAuth2 scope",
    )
    enterprise_auth.add_argument(
        "--ntlm-domain",
        default=None,
        metavar="DOMAIN",
        help="NTLM/Windows authentication domain",
    )

    # CI/CD pipeline integration
    ci_group = parser.add_argument_group("ci/cd integration")
    ci_group.add_argument(
        "--fail-on",
        choices=["critical", "high", "medium", "low"],
        default=None,
        metavar="SEVERITY",
        help="Exit with code 2 if findings at or above this severity exist",
    )

    # Enterprise features
    enterprise_group = parser.add_argument_group("enterprise features")
    enterprise_group.add_argument(
        "--compare-with",
        default=None,
        metavar="FILE",
        help="Compare results with a previous JSON report file",
    )
    enterprise_group.add_argument(
        "--audit-log",
        default=None,
        metavar="FILE",
        help="Enable audit logging to file (default: .w3bsp1d3r/audit.log)",
    )
    enterprise_group.add_argument(
        "--checkpoint",
        action="store_true",
        default=False,
        help="Enable checkpoint/resume for long scans",
    )
    enterprise_group.add_argument(
        "--resume",
        action="store_true",
        default=False,
        help="Resume a previously interrupted scan of the same target (implies --checkpoint)",
    )
    enterprise_group.add_argument(
        "--database",
        default=None,
        metavar="FILE",
        help="Save scan history to SQLite database",
    )
    enterprise_group.add_argument(
        "--plugins-dir",
        default=None,
        metavar="DIR",
        help="Directory containing custom tester plugins",
    )
    enterprise_group.add_argument(
        "--dashboard",
        action="store_true",
        default=False,
        help="Show live rate limit dashboard during scans",
    )

    # Webhook notifications
    webhook_group = parser.add_argument_group("webhook notifications")
    webhook_group.add_argument(
        "--slack-webhook",
        default=None,
        metavar="URL",
        help="Slack incoming webhook URL for scan notifications",
    )
    webhook_group.add_argument(
        "--teams-webhook",
        default=None,
        metavar="URL",
        help="Microsoft Teams webhook URL for scan notifications",
    )
    webhook_group.add_argument(
        "--discord-webhook",
        default=None,
        metavar="URL",
        help="Discord webhook URL for scan notifications",
    )
    webhook_group.add_argument(
        "--webhook-url",
        default=None,
        action="append",
        metavar="URL",
        help="Generic webhook URL (JSON POST). Can be specified multiple times.",
    )

    # API server
    api_group = parser.add_argument_group("api server")
    api_group.add_argument(
        "--api-server",
        action="store_true",
        default=False,
        help="Start the REST API server instead of running a scan",
    )
    api_group.add_argument(
        "--api-host",
        default="127.0.0.1",
        metavar="HOST",
        help="API server host (default: 127.0.0.1)",
    )
    api_group.add_argument(
        "--api-port",
        type=int,
        default=8888,
        metavar="PORT",
        help="API server port (default: 8888)",
    )
    api_group.add_argument(
        "--api-key",
        default=None,
        action="append",
        metavar="KEY",
        help=(
            "API key required to call the server (repeatable). If omitted, the "
            "W3BSP1D3R_API_KEY env var is used. With neither set, auth is DISABLED."
        ),
    )

    return parser


# ---------------------------------------------------------------------------
# Config building
# ---------------------------------------------------------------------------

def _build_config_from_args(args: argparse.Namespace) -> object:
    """
    Build a ScanConfig from CLI arguments, config file, env vars, and profile.

    Priority: CLI args > env vars > config file > profile > defaults
    """
    from scanner.config import ScanConfig, AuthConfig, load_config, load_config_from_env

    # Start with config file if provided
    if args.config:
        config = load_config(
            args.config,
            profile=args.profile,
        )
    else:
        config = ScanConfig()
        if args.profile:
            from scanner.config import _apply_profile
            _apply_profile(config, args.profile)

    # Apply env vars. Most keys live on ScanConfig, but auth-related ones live
    # on config.auth — route those explicitly so they aren't silently dropped.
    env_overrides = load_config_from_env()
    _auth_env_keys = {"login_user": "username", "login_pass": "password",
                      "auth_token": "token"}
    for key, value in env_overrides.items():
        if key in _auth_env_keys:
            setattr(config.auth, _auth_env_keys[key], value)
            if key == "auth_token":
                config.auth.auth_type = "bearer"
            elif config.auth.auth_type == "none":
                config.auth.auth_type = "form"
        elif hasattr(config, key):
            setattr(config, key, value)

    # Apply CLI overrides (highest priority)
    if args.url:
        config.url = args.url
    if args.scan_type:
        config.scan_type = args.scan_type
    if args.threads is not None:
        config.threads = args.threads
    if args.max_pages is not None:
        config.max_pages = args.max_pages
    if args.delay is not None:
        config.delay = args.delay
    if args.timeout is not None:
        config.timeout = args.timeout
    if args.no_verify_ssl:
        config.verify_ssl = False
    if args.render:
        config.render = True
    if args.proxy:
        config.proxy = args.proxy
    if args.output:
        config.output = args.output
    if args.formats:
        config.output_formats = args.formats
    if args.fail_on:
        config.fail_on = args.fail_on
    if args.vt_api_key:
        config.vt_api_key = args.vt_api_key
    if args.vt_delay is not None:
        config.vt_delay = args.vt_delay
    if args.nvd_api_key:
        config.nvd_api_key = args.nvd_api_key
    if args.compare_with:
        config.compare_with = args.compare_with

    # Auth configuration
    if args.login_user:
        config.auth.username = args.login_user
        config.auth.password = args.login_pass
        config.auth.auth_type = "form"
    if args.auth_token:
        config.auth.token = args.auth_token
        config.auth.auth_type = "bearer"
    if args.auth_type:
        config.auth.auth_type = args.auth_type
    if args.oauth2_token_url:
        config.auth.oauth2_token_url = args.oauth2_token_url
    if args.oauth2_client_id:
        config.auth.oauth2_client_id = args.oauth2_client_id
    if args.oauth2_client_secret:
        config.auth.oauth2_client_secret = args.oauth2_client_secret
    if args.oauth2_scope:
        config.auth.oauth2_scope = args.oauth2_scope
    if args.ntlm_domain:
        config.auth.ntlm_domain = args.ntlm_domain

    # Scope control
    if args.include:
        config.scope.include = args.include
    if args.exclude:
        config.scope.exclude = args.exclude

    # Enterprise features
    if args.audit_log:
        config.audit.enabled = True
        config.audit.log_file = args.audit_log
    if args.checkpoint:
        config.checkpoint.enabled = True
    if args.resume:
        config.checkpoint.enabled = True
        config.resume = True
    if args.database:
        config.database.enabled = True
        config.database.path = args.database
    if args.plugins_dir:
        config.plugins.enabled = True
        config.plugins.directories = [args.plugins_dir]
    if args.dashboard:
        config.dashboard = True

    # Webhooks
    if args.slack_webhook or args.teams_webhook or args.discord_webhook or args.webhook_url:
        config.webhooks.enabled = True
    if args.slack_webhook:
        config.webhooks.slack_url = args.slack_webhook
    if args.teams_webhook:
        config.webhooks.teams_url = args.teams_webhook
    if args.discord_webhook:
        config.webhooks.discord_url = args.discord_webhook
    if args.webhook_url:
        config.webhooks.generic_urls = args.webhook_url

    # Logging
    config.verbose = args.verbose
    config.logging.level = "DEBUG" if args.verbose else "WARNING"
    config.logging.format = args.log_format
    if args.log_file:
        config.logging.file = args.log_file

    # Apply policies
    warnings = config.apply_policies()
    for w in warnings:
        print(f"  [Policy] {w}", file=sys.stderr)

    return config


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    """
    Parse arguments, validate inputs, and run the scanner.

    Returns:
        0 on success (even if findings exist — findings ≠ program error).
        1 on configuration or connectivity error.
        2 on security gate failure (--fail-on threshold exceeded).
    """
    parser = _build_parser()
    args   = parser.parse_args()

    # ---- API server mode ----
    if args.api_server:
        _configure_logging(args.verbose, args.log_format, args.log_file)
        from scanner.api import run_api_server
        db = None
        if args.database:
            from scanner.db import ScanDatabase
            db = ScanDatabase(path=args.database)

        # Refuse to expose an unauthenticated scan-launching API on a public
        # interface — that turns the scanner into an open SSRF/abuse proxy.
        auth_enabled = bool(args.api_key) or bool(os.environ.get("W3BSP1D3R_API_KEY"))
        if args.api_host not in ("127.0.0.1", "localhost", "::1") and not auth_enabled:
            parser.error(
                f"Refusing to bind the API to {args.api_host} without authentication. "
                "Set --api-key (or the W3BSP1D3R_API_KEY env var), or bind to 127.0.0.1."
            )
        if not auth_enabled:
            print(
                "\n  [!] API authentication is DISABLED. Anyone who can reach "
                f"{args.api_host}:{args.api_port} can launch scans. "
                "Set --api-key to require a key.\n",
                file=sys.stderr,
            )
        try:
            run_api_server(host=args.api_host, port=args.api_port, db=db,
                           api_keys=args.api_key)
        except KeyboardInterrupt:
            print("\n  API server stopped.", file=sys.stderr)
        return 0

    # ---- Build config ----
    config = _build_config_from_args(args)

    # Validate URL
    if not config.url:
        parser.error(
            "Target URL is required. Use --url or set it in the config file."
        )
    if not config.url.startswith(("http://", "https://")):
        parser.error(
            f"Invalid URL '{config.url}' — must start with http:// or https://"
        )

    # Bounds-check numeric arguments
    if not (1 <= config.threads <= 128):
        parser.error("--threads must be between 1 and 128")
    if not (1 <= config.max_pages <= 10_000):
        parser.error("--max-pages must be between 1 and 10000")
    if config.delay < 0:
        parser.error("--delay cannot be negative")
    if not (1 <= config.timeout <= 300):
        parser.error("--timeout must be between 1 and 300 seconds")

    # Warn if both login args aren't provided together
    if bool(config.auth.username) != bool(config.auth.password):
        if config.auth.auth_type == "form":
            parser.error(
                "--login-user and --login-pass must both be provided together."
            )

    # Configure logging
    _configure_logging(
        config.verbose,
        config.logging.format,
        config.logging.file,
        quiet=args.quiet,
    )

    # Quiet console mode for CI/CD (does not affect file logging or reports)
    if args.quiet:
        from scanner.utils.display import set_quiet
        set_quiet(True)

    # Sanitize output path — block directory traversal
    try:
        cwd = Path.cwd()
        resolved = (cwd / config.output).resolve()
        resolved.relative_to(cwd)
    except ValueError:
        parser.error(
            f"Invalid --output path '{config.output}' — must stay within the current directory."
        )
    config.output = str(resolved.with_suffix(""))

    # Warn about --no-verify-ssl
    if not config.verify_ssl:
        print(
            "\n  [!] TLS verification disabled. Only use this in isolated lab environments.\n",
            file=sys.stderr,
        )

    # Warn about proxy usage
    if config.proxy:
        print(
            f"\n  [*] Proxy enabled: routing all traffic through {config.proxy}\n",
            file=sys.stderr,
        )

    # ---- Create and run scanner ----
    scanner = WebVulnScanner(
        url=config.url,
        config=config,
    )

    try:
        scanner.scan()
    except KeyboardInterrupt:
        print("\n\n  [!] Scan interrupted by user.", file=sys.stderr)
        return 1
    except Exception as exc:
        logging.getLogger(__name__).exception("Unhandled error during scan")
        print(f"\n  [!] Fatal error: {exc}", file=sys.stderr)
        return 1

    # CI/CD exit code: 2 = security policy violation
    if scanner.should_fail():
        print(
            f"\n  [!] Security gate FAILED: findings at or above "
            f"'{config.fail_on}' severity detected (exit code 2).",
            file=sys.stderr,
        )
        return 2

    return 0


if __name__ == "__main__":
    sys.exit(main())
