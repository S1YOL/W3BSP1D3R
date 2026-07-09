#!/usr/bin/env python3
from __future__ import annotations
"""
gui.py — Streamlit GUI for W3BSP1D3R.

Usage:
  streamlit run gui.py

by S1YOL.

LEGAL WARNING:
  I AM NOT RESPONSIBLE FOR ANYONE USING THIS APP.
  Scanning without authorization is a FEDERAL CRIME under the Computer Fraud
  and Abuse Act (CFAA, 18 U.S.C. 1030). Only scan systems you own or have
  explicit written permission to test.
"""

import logging
import sys
import time
import threading
from datetime import datetime, timezone
from io import StringIO
from pathlib import Path

import streamlit as st

# ---------------------------------------------------------------------------
# Page configuration — must be the first Streamlit call
# ---------------------------------------------------------------------------
st.set_page_config(
    page_title="W3BSP1D3R v1.0.0",
    page_icon="🕷️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ---------------------------------------------------------------------------
# Imports from the scanner package
# ---------------------------------------------------------------------------
from scanner.core import WebVulnScanner
from scanner.reporting.models import Severity

# ---------------------------------------------------------------------------
# Logging — send scanner log output to a buffer we can display
# ---------------------------------------------------------------------------
_log_buffer = StringIO()
logging.basicConfig(
    level=logging.WARNING,
    format="%(asctime)s [%(levelname)-8s] %(name)s: %(message)s",
    datefmt="%H:%M:%S",
    handlers=[logging.StreamHandler(_log_buffer)],
    force=True,
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
SCAN_TYPES = {
    "Full Scan (all 17 tests)":          "full",
    "Passive (no attack payloads)":      "passive",
    "SQL Injection":                     "sqli",
    "Cross-Site Scripting (XSS)":        "xss",
    "CSRF":                              "csrf",
    "Command Injection":                 "cmdi",
    "SSTI (Template Injection)":         "ssti",
    "NoSQL Injection":                   "nosqli",
    "Path Traversal":                    "traversal",
    "Open Redirect":                     "redirect",
    "IDOR":                              "idor",
    "Security Headers":                  "headers",
    "Cookie Security":                   "cookies",
    "CORS Misconfiguration":             "cors",
    "SSL/TLS Analysis":                  "ssl",
    "Sensitive Files":                   "files",
    "WAF Detection":                     "waf",
    "Subdomain Enumeration":             "subdomains",
    "CVE Lookup":                        "cve",
    "Directory Discovery":               "dirs",
    "HTTP Method Testing":               "methods",
    "Technology Fingerprinting":         "fingerprint",
    "XXE (XML Entity Injection)":        "xxe",
    "JWT Security Testing":              "jwt",
    "Information Disclosure":            "info",
    "Rate Limit Testing":               "ratelimit",
    "Clickjacking Protection":           "clickjack",
}

AUTH_TYPES = {
    "None":                 "none",
    "Form Login":           "form",
    "Bearer / JWT Token":   "bearer",
    "OAuth2":               "oauth2",
    "NTLM (Windows)":       "ntlm",
    "API Key":              "apikey",
}

REPORT_FORMATS = ["html", "md", "json", "sarif", "pdf"]

SEV_COLORS = {
    "Critical": "#ff2d2d",
    "High":     "#ff6a00",
    "Medium":   "#ffc107",
    "Low":      "#00b0ff",
}

SEV_EMOJI = {
    "Critical": "🔴",
    "High":     "🟠",
    "Medium":   "🟡",
    "Low":      "🔵",
}

# ---------------------------------------------------------------------------
# Custom CSS — dark W3BSP1D3R theme
# ---------------------------------------------------------------------------
st.markdown("""
<style>
    .stApp { background-color: #0a0a0f; }

    .header-box {
        background: linear-gradient(135deg, #150000 0%, #0a0a0f 50%, #000a15 100%);
        border: 1px solid #cc0000;
        border-radius: 10px;
        padding: 24px 30px;
        margin-bottom: 24px;
        position: relative;
        overflow: hidden;
    }
    .header-box::before {
        content: '';
        position: absolute;
        top: 0; left: 0; right: 0;
        height: 3px;
        background: linear-gradient(90deg, transparent, #cc0000, transparent);
    }
    .header-title {
        font-family: 'Cascadia Code', 'Fira Code', monospace;
        color: #ffffff;
        font-size: 2.2em;
        font-weight: 800;
        letter-spacing: 6px;
    }
    .header-title .red { color: #ff2d2d; }
    .header-sub {
        color: #8888a0;
        font-size: 0.9em;
        margin-top: 2px;
        letter-spacing: 2px;
    }
    .header-meta {
        display: flex;
        gap: 24px;
        margin-top: 10px;
        font-family: monospace;
        font-size: 0.8em;
    }
    .header-meta span { color: #666; }
    .header-meta b { color: #ff2d2d; }

    .finding-card {
        border-radius: 8px;
        padding: 18px;
        margin-bottom: 14px;
        border-left: 4px solid;
        background: #12121a;
    }
    .finding-critical { border-left-color: #ff2d2d; }
    .finding-high     { border-left-color: #ff6a00; }
    .finding-medium   { border-left-color: #ffc107; }
    .finding-low      { border-left-color: #00b0ff; }

    .finding-header {
        display: flex;
        justify-content: space-between;
        align-items: center;
        margin-bottom: 10px;
    }
    .finding-type {
        font-size: 1.05em;
        font-weight: 700;
        color: #e0e0e8;
    }
    .sev-pill {
        font-size: 0.75em;
        font-weight: 700;
        padding: 3px 10px;
        border-radius: 3px;
        color: white;
        letter-spacing: 0.5px;
    }
    .sev-pill-critical { background: #ff2d2d; }
    .sev-pill-high { background: #ff6a00; }
    .sev-pill-medium { background: #ffc107; color: #1a1a00; }
    .sev-pill-low { background: #00b0ff; }

    .finding-table {
        width: 100%;
        color: #b0b0c0;
        font-size: 0.85em;
        border-collapse: collapse;
    }
    .finding-table td {
        padding: 3px 0;
        vertical-align: top;
    }
    .finding-table .lbl {
        width: 100px;
        color: #666680;
        font-weight: 600;
        text-transform: uppercase;
        font-size: 0.8em;
        letter-spacing: 0.5px;
    }
    .finding-table code {
        background: #1a1a24;
        padding: 1px 6px;
        border-radius: 3px;
        font-size: 0.9em;
        color: #ff2d2d;
    }
    .payload-text {
        color: #ff8888;
        font-family: 'Cascadia Code', monospace;
        background: rgba(255,45,45,0.06);
        padding: 2px 6px;
        border-radius: 3px;
    }
    .evidence-text { color: #8888a0; font-style: italic; }
    .fix-text { color: #88ddaa; }

    .stat-card {
        background: #12121a;
        border: 1px solid #2a2a3a;
        border-radius: 8px;
        padding: 18px 12px;
        text-align: center;
        transition: border-color 0.2s;
    }
    .stat-card:hover { border-color: #ff2d2d; }
    .stat-val {
        font-size: 2.2em;
        font-weight: 700;
        font-family: 'Cascadia Code', monospace;
    }
    .stat-lbl {
        color: #666680;
        font-size: 0.75em;
        text-transform: uppercase;
        letter-spacing: 1px;
        margin-top: 2px;
    }

    .warning-box {
        background: rgba(255,45,45,0.05);
        border-left: 3px solid #cc0000;
        border-radius: 0 6px 6px 0;
        padding: 10px 14px;
        color: #ff8888;
        font-size: 0.8em;
        margin-bottom: 16px;
    }

    .dl-section {
        background: #12121a;
        border: 1px solid #2a2a3a;
        border-radius: 8px;
        padding: 16px;
        margin-top: 16px;
    }

    /* Sidebar styling */
    section[data-testid="stSidebar"] {
        background-color: #0e0e16;
    }
    section[data-testid="stSidebar"] .stMarkdown h2 {
        color: #ff2d2d;
        font-family: monospace;
        letter-spacing: 2px;
    }
    section[data-testid="stSidebar"] .stMarkdown h4 {
        color: #8888a0;
        letter-spacing: 1px;
    }
</style>
""", unsafe_allow_html=True)


# ---------------------------------------------------------------------------
# Header
# ---------------------------------------------------------------------------
st.markdown("""
<div class="header-box">
    <div class="header-title">W<span class="red">3</span>BSP<span class="red">1</span>D<span class="red">3</span>R</div>
    <div class="header-sub">Web Vulnerability Scanner</div>
    <div class="header-meta">
        <span>Version <b>v1.0.0</b></span>
        <span>Build <b>S1YOL</b></span>
        <span>Modules <b>17</b></span>
        <span>Formats <b>5</b></span>
    </div>
</div>
""", unsafe_allow_html=True)


# ---------------------------------------------------------------------------
# Sidebar — scan configuration
# ---------------------------------------------------------------------------
with st.sidebar:
    st.markdown("## W3BSP1D3R")

    st.markdown("""
    <div class="warning-box">
        <b>AUTHORISED TESTING ONLY</b><br>
        Only scan systems you own or have explicit written permission to test.
        The author assumes no responsibility for misuse.
    </div>
    """, unsafe_allow_html=True)

    # ── Target ──
    st.markdown("#### TARGET")
    target_url = st.text_input(
        "Target URL",
        placeholder="http://localhost/dvwa",
        help="Base URL of the web application to scan.",
    )

    scan_type_label = st.selectbox("Scan Type", list(SCAN_TYPES.keys()))
    scan_type = SCAN_TYPES[scan_type_label]

    # ── Authentication ──
    st.markdown("#### AUTHENTICATION")
    auth_type_label = st.selectbox("Auth Method", list(AUTH_TYPES.keys()))
    auth_type = AUTH_TYPES[auth_type_label]

    login_user = ""
    login_pass = ""
    auth_token = ""
    oauth2_token_url = ""
    oauth2_client_id = ""
    oauth2_client_secret = ""
    oauth2_scope = ""
    ntlm_domain = ""

    if auth_type == "form":
        login_user = st.text_input("Username", placeholder="admin")
        login_pass = st.text_input("Password", placeholder="password", type="password")
    elif auth_type == "bearer":
        auth_token = st.text_input("Bearer / JWT Token", type="password",
                                   placeholder="eyJhbGciOiJIUzI1NiIs...")
    elif auth_type == "oauth2":
        oauth2_token_url = st.text_input("Token URL", placeholder="https://auth.example.com/oauth/token")
        oauth2_client_id = st.text_input("Client ID")
        oauth2_client_secret = st.text_input("Client Secret", type="password")
        oauth2_scope = st.text_input("Scope", placeholder="read write")
    elif auth_type == "ntlm":
        login_user = st.text_input("Username", placeholder="admin")
        login_pass = st.text_input("Password", type="password")
        ntlm_domain = st.text_input("Domain", placeholder="CORP")
    elif auth_type == "apikey":
        auth_token = st.text_input("API Key", type="password", placeholder="sk-abc123...")

    # ── Scan Settings ──
    st.markdown("#### SCAN SETTINGS")
    max_pages = st.slider("Max Pages", 1, 500, 50)
    threads = st.slider("Threads", 1, 16, 4)
    delay = st.slider("Request Delay (s)", 0.0, 5.0, 0.5, step=0.1)
    timeout = st.slider("Timeout (s)", 1, 60, 10)
    verify_ssl = st.checkbox("Verify SSL", value=True)

    # ── Output ──
    st.markdown("#### OUTPUT")
    output_name = st.text_input("Report Filename", value="scan_report",
                                help="Base name for reports (no extension).")
    report_formats = st.multiselect("Report Formats", REPORT_FORMATS,
                                    default=["html", "md", "json", "sarif"])

    # ── Network ──
    with st.expander("Network / Proxy"):
        proxy = st.text_input("Proxy URL", placeholder="http://127.0.0.1:8080",
                              help="Route traffic through Burp Suite or other proxy.")

    # ── API Keys ──
    with st.expander("API Keys"):
        vt_api_key = st.text_input("VirusTotal API Key", type="password",
                                   help="Free key from virustotal.com")
        vt_delay = st.number_input("VT Request Delay (s)", value=15.0, min_value=1.0)
        nvd_api_key = st.text_input("NVD API Key", type="password",
                                    help="Free key from nvd.nist.gov")

    # ── Enterprise ──
    with st.expander("Enterprise Features"):
        enable_checkpoint = st.checkbox("Enable Checkpoint/Resume",
                                        help="Save progress for crash recovery.")
        enable_dashboard = st.checkbox("Enable Rate Limit Dashboard",
                                       help="Live terminal metrics during scan.")
        fail_on = st.selectbox("CI/CD Fail Threshold",
                               ["None", "critical", "high", "medium", "low"],
                               help="Exit code 2 if findings meet this severity.")
        compare_with = st.text_input("Compare With (JSON file)",
                                     placeholder="previous_scan.json",
                                     help="Diff against a baseline scan.")

    # ── Start Button ──
    st.markdown("---")
    start_scan = st.button("🕷️ START SCAN", type="primary", use_container_width=True)


# ---------------------------------------------------------------------------
# Helper: build config and run scan
# ---------------------------------------------------------------------------
def _run_scan():
    """Execute the scanner and store results in session state."""
    from scanner.config import ScanConfig

    # Sanitize output path
    cwd = Path.cwd()
    resolved = (cwd / output_name).resolve()
    try:
        resolved.relative_to(cwd)
    except ValueError:
        st.session_state["scan_error"] = "Invalid report path — must stay within the project directory."
        return
    safe_output = str(resolved.with_suffix(""))

    # Build config
    config = ScanConfig()
    config.url = target_url
    config.scan_type = scan_type
    config.max_pages = max_pages
    config.threads = threads
    config.delay = delay
    config.timeout = timeout
    config.verify_ssl = verify_ssl
    config.output = safe_output
    config.output_formats = list(report_formats)
    config.proxy = proxy if proxy else None
    config.vt_api_key = vt_api_key if vt_api_key else None
    config.vt_delay = vt_delay
    config.nvd_api_key = nvd_api_key if nvd_api_key else None
    config.compare_with = compare_with if compare_with else None
    config.dashboard = enable_dashboard

    if fail_on and fail_on != "None":
        config.fail_on = fail_on

    # Auth
    config.auth.auth_type = auth_type
    if auth_type == "form":
        config.auth.username = login_user or None
        config.auth.password = login_pass or None
    elif auth_type in ("bearer", "apikey"):
        config.auth.token = auth_token or None
    elif auth_type == "oauth2":
        config.auth.oauth2_token_url = oauth2_token_url or None
        config.auth.oauth2_client_id = oauth2_client_id or None
        config.auth.oauth2_client_secret = oauth2_client_secret or None
        config.auth.oauth2_scope = oauth2_scope or None
    elif auth_type == "ntlm":
        config.auth.username = login_user or None
        config.auth.password = login_pass or None
        config.auth.ntlm_domain = ntlm_domain or None

    # Checkpoint
    if enable_checkpoint:
        config.checkpoint.enabled = True

    # Apply policies
    config.apply_policies()

    scanner = WebVulnScanner(url=target_url, config=config)

    try:
        summary = scanner.scan()
        st.session_state["scan_summary"] = summary
        st.session_state["scan_error"] = None
        st.session_state["scan_output"] = safe_output
    except Exception as exc:
        st.session_state["scan_error"] = str(exc)
        st.session_state["scan_summary"] = None


# ---------------------------------------------------------------------------
# Main area — scan execution and results
# ---------------------------------------------------------------------------
if start_scan:
    if not target_url:
        st.error("Enter a target URL in the sidebar.")
    elif not target_url.startswith(("http://", "https://")):
        st.error("URL must start with **http://** or **https://**")
    elif auth_type == "form" and (bool(login_user) != bool(login_pass)):
        st.error("Provide both username and password, or leave both empty.")
    else:
        with st.spinner("🕷️ Scanning in progress — this may take a few minutes..."):
            _run_scan()

        if st.session_state.get("scan_error"):
            st.error(f"Scan failed: {st.session_state['scan_error']}")

# ---------------------------------------------------------------------------
# Display results
# ---------------------------------------------------------------------------
summary = st.session_state.get("scan_summary")

if summary:
    st.markdown("---")

    # ── Severity stat cards ──
    cols = st.columns(5)
    stats = [
        ("Critical", summary.critical_count, "#ff2d2d"),
        ("High", summary.high_count, "#ff6a00"),
        ("Medium", summary.medium_count, "#ffc107"),
        ("Low", summary.low_count, "#00b0ff"),
        ("Total", summary.total_findings, "#ffffff"),
    ]
    for col, (label, count, color) in zip(cols, stats):
        with col:
            st.markdown(f"""<div class="stat-card">
                <div class="stat-val" style="color: {color};">{count}</div>
                <div class="stat-lbl">{label}</div>
            </div>""", unsafe_allow_html=True)

    st.markdown("")

    # ── Scan details ──
    with st.expander("📊 Scan Details", expanded=True):
        c1, c2, c3 = st.columns(3)
        with c1:
            st.markdown(f"**Target:** `{summary.target_url}`")
            st.markdown(f"**Scan Type:** `{summary.scan_type}`")
        with c2:
            st.markdown(f"**Pages Crawled:** {summary.pages_crawled}")
            st.markdown(f"**Forms Found:** {summary.forms_found}")
        with c3:
            st.markdown(f"**Params Tested:** {summary.params_tested}")
            st.markdown(f"**Started:** {summary.started_at}")
            st.markdown(f"**Finished:** {summary.finished_at}")

    # ── Findings ──
    if summary.total_findings == 0:
        st.success("No vulnerabilities found — the target looks clean.")
    else:
        st.markdown(f"### 🕷️ Findings ({summary.total_findings})")

        # Filters
        filter_col1, filter_col2 = st.columns([2, 3])
        with filter_col1:
            sev_filter = st.multiselect(
                "Severity", ["Critical", "High", "Medium", "Low"],
                default=["Critical", "High", "Medium", "Low"],
            )
        with filter_col2:
            # Get unique vuln types
            vuln_types = sorted(set(f.vuln_type for f in summary.findings))
            type_filter = st.multiselect("Vulnerability Type", vuln_types, default=vuln_types)

        for finding in summary.sorted_findings():
            if finding.severity not in sev_filter:
                continue
            if finding.vuln_type not in type_filter:
                continue

            sev_class = f"finding-{finding.severity.lower()}"
            pill_class = f"sev-pill-{finding.severity.lower()}"
            emoji = SEV_EMOJI.get(finding.severity, "⚪")

            st.markdown(f"""
            <div class="finding-card {sev_class}">
                <div class="finding-header">
                    <span class="finding-type">{emoji} {finding.vuln_type}</span>
                    <span class="sev-pill {pill_class}">{finding.severity.upper()}</span>
                </div>
                <table class="finding-table">
                    <tr><td class="lbl">URL</td><td><code>{finding.url}</code></td></tr>
                    <tr><td class="lbl">Param</td><td><code>{finding.parameter}</code></td></tr>
                    <tr><td class="lbl">Method</td><td>{finding.method}</td></tr>
                    <tr><td class="lbl">Payload</td><td><span class="payload-text">{finding.payload}</span></td></tr>
                    <tr><td class="lbl">Evidence</td><td><span class="evidence-text">{finding.evidence[:300]}</span></td></tr>
                    <tr><td class="lbl">Fix</td><td><span class="fix-text">{finding.remediation}</span></td></tr>
                </table>
            </div>
            """, unsafe_allow_html=True)

    # ── Report Downloads ──
    st.markdown("### 📄 Download Reports")
    report_base = st.session_state.get("scan_output", output_name)
    cwd = Path.cwd()

    report_files = [
        (".html", "HTML Report", "text/html"),
        (".md",   "Markdown",    "text/markdown"),
        (".json", "JSON",        "application/json"),
        (".sarif","SARIF",       "application/json"),
        (".pdf",  "PDF",         "application/pdf"),
    ]

    dl_cols = st.columns(len(report_files))
    for col, (ext, label, mime) in zip(dl_cols, report_files):
        resolved = (cwd / report_base).resolve().with_suffix(ext)
        with col:
            if resolved.exists():
                st.download_button(
                    label=f"⬇ {label}",
                    data=resolved.read_bytes(),
                    file_name=resolved.name,
                    mime=mime,
                    use_container_width=True,
                )
            else:
                st.button(f"{label}", disabled=True, use_container_width=True)

    # ── Log Output ──
    log_content = _log_buffer.getvalue()
    if log_content:
        with st.expander("📋 Scanner Log Output"):
            st.code(log_content, language="text")

elif not start_scan:
    # ── Landing page ──
    st.markdown("")
    st.markdown("""
    <div style="text-align: center; padding: 50px 20px; color: #555;">
        <div style="font-size: 4em; margin-bottom: 8px;">🕷️</div>
        <div style="font-family: 'Cascadia Code', monospace; font-size: 1.4em; color: #ff2d2d;
                    letter-spacing: 4px; margin-bottom: 12px; font-weight: 700;">
            W3BSP1D3R
        </div>
        <div style="font-size: 1em; color: #666; margin-bottom: 30px;">
            Configure your scan in the sidebar and click <b style="color: #ff2d2d;">START SCAN</b>
        </div>
        <div style="display: flex; justify-content: center; gap: 40px; flex-wrap: wrap; margin-bottom: 30px;">
            <div style="text-align: center;">
                <div style="font-size: 1.8em; color: #ff2d2d; font-weight: 700;">17</div>
                <div style="color: #555; font-size: 0.8em; text-transform: uppercase; letter-spacing: 1px;">Test Modules</div>
            </div>
            <div style="text-align: center;">
                <div style="font-size: 1.8em; color: #ff2d2d; font-weight: 700;">5</div>
                <div style="color: #555; font-size: 0.8em; text-transform: uppercase; letter-spacing: 1px;">Report Formats</div>
            </div>
            <div style="text-align: center;">
                <div style="font-size: 1.8em; color: #ff2d2d; font-weight: 700;">6</div>
                <div style="color: #555; font-size: 0.8em; text-transform: uppercase; letter-spacing: 1px;">Auth Methods</div>
            </div>
        </div>
        <div style="font-size: 0.8em; color: #444; max-width: 450px; margin: 0 auto;">
            SQLi · XSS · CSRF · CMDi · SSTI · NoSQLi · Path Traversal · Open Redirect · IDOR ·
            Headers · Cookies · CORS · SSL/TLS · WAF · Subdomains · CVE · Sensitive Files
        </div>
    </div>
    """, unsafe_allow_html=True)
