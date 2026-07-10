# W3BSP1D3R

**Web vulnerability scanner built in Python — 26 test modules, headless-browser rendering for JavaScript/SPA targets, REST/JSON API fuzzing, 5 report formats, YAML config profiles, enterprise auth, plugin system, REST API server, and structured logging. Built for labs, authorised pentesting, and CI/CD pipelines.**

```
 ██╗    ██╗ ██████╗ ██████╗ ███████╗██████╗  ██╗██████╗ ██████╗ ██████╗
 ██║    ██║ ╚════██╗██╔══██╗██╔════╝██╔══██╗███║██╔══██╗╚════██╗██╔══██╗
 ██║ █╗ ██║  █████╔╝██████╔╝███████╗██████╔╝╚██║██║  ██║ █████╔╝██████╔╝
 ██║███╗██║  ╚═══██╗██╔══██╗╚════██║██╔═══╝  ██║██║  ██║ ╚═══██╗██╔══██╗
 ╚███╔███╔╝ ██████╔╝██████╔╝███████║██║      ██║██████╔╝██████╔╝██║  ██║
  ╚══╝╚══╝  ╚═════╝ ╚═════╝ ╚══════╝╚═╝      ╚═╝╚═════╝ ╚═════╝ ╚═╝  ╚═╝
```

[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-1.0.0-blueviolet.svg)](#)
[![Tests](https://img.shields.io/badge/tests-140%20passing-brightgreen.svg)](#running-tests)
[![Release](https://img.shields.io/badge/release-v1.0.0%20official-brightgreen.svg)](#)

---

## Legal Disclaimer

> **This tool is provided strictly for authorised security testing and educational purposes.**
>
> You **must** only scan:
> - Systems you have **explicit written authorisation** to test
> - Intentionally vulnerable lab environments (DVWA, Juice Shop, HackTheBox, TryHackMe, etc.)
>
> Unauthorised scanning is a criminal offence under the Computer Fraud and Abuse Act (CFAA, 18 U.S.C. § 1030), the Computer Misuse Act 1990 (UK), and equivalent legislation in your jurisdiction. **The author of this software bears no responsibility whatsoever for any damages, legal consequences, or misuse arising from the use of this tool.** By downloading or using W3BSP1D3R, you agree that you assume all responsibility for your actions and that the author shall not be held liable under any circumstances.

---

## Highlights in v1.0.0

This is the official **v1.0.0** release. Beyond the full enterprise feature set below, v1.0.0 adds true JavaScript/SPA coverage, live-app interaction, REST/JSON API fuzzing, and a completely redesigned interactive HTML report:

| Feature | Description |
|---------|-------------|
| **Interactive HTML Report** | Client-ready security-assessment document — overall-risk verdict, severity donut, OWASP Top 10 mapping, prioritised remediation roadmap, per-finding CWE/CVSS/confidence metadata, live search & severity filters, light/dark themes, and one-click print-to-PDF |
| **JavaScript / SPA Rendering** | `--render` loads each page in headless Chromium, hydrates the SPA, and crawls the rendered DOM — finding JS-generated links and forms the static crawler can't see |
| **DOM-Based XSS** | Browser-verified DOM-XSS tester proves client-side execution by firing `alert()` from payloads injected into the URL fragment and query params |
| **Interaction-Driven Crawling** | `--interact` drives safe, bounded SPA interactions (submit search, fill forms with benign values, click non-destructive controls) so hidden REST/JSON endpoints fire and get discovered |
| **SPA Hash-Route Discovery** | Enumerates client-side hash routes (`#/path`) so single-page-app views are crawled, not just the shell |
| **REST / JSON API Fuzzing** | Injectable JSON API endpoints revealed during rendering are fuzzed for injection flaws, not just HTML forms |
| **Safe Concurrent Scans** | Per-scan state isolation lets the REST API server run multiple scans at once without cross-contamination (multi-tenancy) |
| **Quiet Mode** | `--quiet` suppresses banner/progress noise for clean CI/CD logs while still printing findings and the summary |
| **YAML Config Profiles** | Load reusable configs with `--config` and `--profile` |
| **Enterprise Auth** | OAuth2, NTLM, API key, custom header authentication |
| **Structured JSON Logging** | SIEM/ELK-ready `--log-format json` output |
| **Scan Scope Control** | `--include` and `--exclude` URL patterns |
| **Finding Deduplication** | Automatic SHA-256 fingerprinting eliminates duplicates |
| **Checkpoint/Resume** | Crash recovery for long scans via `--checkpoint` |
| **Audit Trail** | Compliance-ready audit logging via `--audit-log` |
| **Historical Database** | SQLite trend tracking via `--database` |
| **Plugin System** | Drop-in custom testers via `--plugins-dir` |
| **PDF Reports** | Native PDF generation via `fpdf2` |
| **Report Diff/Comparison** | Compare scans with `--compare-with` |
| **REST API Server** | Remote control via `--api-server` |
| **Webhook Notifications** | Slack, Teams, Discord, and custom webhook alerts |
| **Rate Limit Dashboard** | Live terminal metrics via `--dashboard` |
| **Parallel scanning** | Thread-pool engine with per-thread HTTP sessions |
| **OWASP Top 10 Mapping** | Every finding mapped to OWASP 2021 categories |
| **Jira / ServiceNow** | Auto-create tickets from findings |
| **Email Notifications** | SMTP scan reports with HTML formatting |
| **Scan Scheduler** | Cron-based recurring scans |
| **Custom Payloads** | Load payloads from YAML/JSON files |
| **Docker Support** | Dockerfile + docker-compose for containerised deployment |
| **GitHub Actions CI** | Automated testing and linting on push/PR |
| **API Authentication** | API key auth on the REST API server |
| **Environment Variables** | Full `W3BSP1D3R_*` env var support |

---

## What It Does

W3BSP1D3R crawls a target website, maps every form and URL parameter, fires attack payloads against each one, and reports what's vulnerable — with the exact payload that triggered it and how to fix it.

### Test Modules

| Category | Modules |
|----------|---------|
| **Injection** | SQL Injection (error, UNION, boolean-blind, time-blind) · NoSQL Injection · Command Injection · SSTI · XXE |
| **Client-Side** | Reflected XSS · Stored XSS · DOM-based XSS (browser-verified) · CSRF · Open Redirect · Clickjacking |
| **Access Control** | Path Traversal · IDOR · JWT Weaknesses · Sensitive File Exposure (`.env`, `.git/`, backups, admin panels) · Directory Discovery |
| **Configuration** | Security Headers · Cookie Security · CORS Misconfiguration · SSL/TLS · WAF Detection · HTTP Methods · Rate-Limit Checks |
| **Recon** | Subdomain Enumeration · Technology Fingerprinting · Information Disclosure · CVE Lookup (NVD) · VirusTotal Threat Intelligence |

### Detection Quality

This isn't a grep-for-strings scanner. It uses real detection techniques to minimise false positives:

- **Baseline comparison** — fetches a clean response before injecting, skips error signatures that already exist in normal output
- **3-way boolean SQLi** — TRUE must match baseline AND FALSE must differ, plus a recheck gate
- **Structural XSS verification** — confirms payload elements (tags, event handlers) survived encoding in the response
- **Regex-confirmed command injection** — matches `uid=\d+\(\w+\) gid=\d+` format, not just the substring "uid="
- **SSRF protection** — the scanner itself blocks redirects to private IPs and out-of-scope origins
- **XXE-safe XML parsing** — sitemap parsing uses defusedxml to prevent the scanner from being attacked
- **Finding deduplication** — SHA-256 fingerprints prevent the same vulnerability from being reported twice

---

## Requirements

- **Python 3.10 or newer**
- **pip** (comes with Python)
- **Docker** (optional — only needed to run DVWA / Juice Shop targets)
- **Git** (optional — you can also download the .zip)

### Check your Python version

```bash
python3 --version       # Linux / macOS
python --version        # Windows
```

If you don't have Python, download it from [python.org](https://www.python.org/downloads/).

> **Windows users:** During installation, check **"Add Python to PATH"** — if you skip this, nothing will work from the command line.

---

## Installation

### Option 1: Git Clone (all platforms)

```bash
git clone https://github.com/S1YOL/W3BSP1D3R.git
cd W3BSP1D3R
```

### Option 2: Download from Releases

Go to [Releases](https://github.com/S1YOL/W3BSP1D3R/releases) and download:
- **Windows** → `W3BSP1D3R-v1.0.0-windows.zip` — right-click → Extract All
- **macOS** → `W3BSP1D3R-v1.0.0-macos.tar.gz` — extract with `tar -xzf W3BSP1D3R-v1.0.0-macos.tar.gz`
- **Linux** → `W3BSP1D3R-v1.0.0-linux.tar.gz` — extract with `tar -xzf W3BSP1D3R-v1.0.0-linux.tar.gz`

Then `cd` into the extracted folder.

---

## Setup

### Windows — One-Click Launcher (easiest)

**No terminal knowledge required.** Just double-click `W3BSP1D3R.bat` in the extracted folder.

On first run it will:
1. Check that Python 3.10+ is installed
2. Automatically create a virtual environment
3. Install all dependencies
4. Open a menu where you can pick what to do

The menu gives you these options:

| Option | What it does |
|--------|-------------|
| **1 — Quick Scan** | Enter a URL and run a full vulnerability scan |
| **2 — SQLi-Only** | Test only for SQL injection |
| **3 — XSS-Only** | Test only for cross-site scripting |
| **4 — Passive Scan** | Check headers, SSL, cookies, etc. (no attack payloads sent) |
| **5 — Authenticated Scan** | Log in with username/password, then full scan |
| **6 — Custom Command** | Type your own CLI arguments |
| **7 — Start GUI** | Launch the Streamlit web interface in your browser |
| **8 — Build Standalone EXE** | Compile a portable `.exe` you can share (see below) |

> **Prerequisite:** You still need [Python 3.10+](https://www.python.org/downloads/) installed. During installation, check **"Add Python to PATH"** — if you skip this, nothing will work.

### Windows — Build a Standalone `.exe`

If you want a single `W3BSP1D3R.exe` that runs on any Windows machine **without Python installed**:

1. Double-click `W3BSP1D3R.bat`
2. Select option **8 — Build Standalone EXE**
3. Wait for PyInstaller to finish (takes a few minutes the first time)
4. Your `.exe` will be at `dist\W3BSP1D3R.exe`

You can copy `W3BSP1D3R.exe` to any Windows computer and run it directly:

```cmd
W3BSP1D3R.exe --url http://localhost/dvwa --login-user admin --login-pass password
```

No Python, no pip, no virtual environment — just the `.exe` and you're scanning.

### Windows — Manual Setup (Command Prompt)

If you prefer doing it yourself:

```cmd
setup.bat
venv\Scripts\activate
```

Or fully manual:

```cmd
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
```

### Windows — Manual Setup (PowerShell)

```powershell
.\setup.bat
.\venv\Scripts\Activate.ps1
```

> **PowerShell note:** If you get a script execution error, run `Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser` first.

### Linux / macOS — One-Click Launcher (easiest)

**Option A — Add to your app menu (recommended):**

```bash
chmod +x install.sh
./install.sh
```

This adds W3BSP1D3R to your application menu. You can then search "W3BSP1D3R" in your app launcher and open it like any other app.

**Option B — Run from terminal:**

```bash
chmod +x W3BSP1D3R.sh
./W3BSP1D3R.sh
```

Both options auto-create a virtual environment and install dependencies on first run. Then you get an interactive menu (Quick Scan, SQLi, XSS, Passive, Authenticated, Custom, GUI).

> **Prerequisite:** Python 3.10+ must be installed. See [Requirements](#requirements).
>
> **Arch Linux:** `sudo pacman -S python` if you don't have it already.

### Linux — Manual Setup

```bash
chmod +x setup.sh
./setup.sh
source venv/bin/activate
```

Or fully manual:

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### macOS — Manual Setup

```bash
chmod +x setup.sh
./setup.sh
source venv/bin/activate
```

Or fully manual:

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

> **macOS note:** If you get `xcrun: error: invalid active developer path`, run `xcode-select --install` first to install command line tools.

### Verify it works (all platforms)

```bash
python main.py --help
```

You should see the full help output with all available options. If you see an error, make sure your virtual environment is activated (you should see `(venv)` at the start of your terminal prompt).

---

## Setting Up a Target

You need a deliberately vulnerable app to scan. **Do not scan any system without explicit authorisation. The author is not responsible for any consequences resulting from unauthorised use.**

### DVWA (recommended for beginners)

Requires [Docker](https://docs.docker.com/get-docker/).

```bash
docker run --rm -d -p 80:80 --name dvwa vulnerables/web-dvwa
```

Go to `http://localhost/dvwa/setup.php` → click **Create / Reset Database** → login with `admin` / `password`.

> **Windows:** If port 80 is taken (common with IIS or Skype), use `-p 8080:80` instead and scan `http://localhost:8080/dvwa`.

### OWASP Juice Shop

```bash
docker run --rm -d -p 3000:3000 --name juiceshop bkimminich/juice-shop
```

### Both at once (Docker Compose)

```yaml
# docker-compose.yml
version: "3.9"
services:
  dvwa:
    image: vulnerables/web-dvwa
    ports: ["80:80"]
  juiceshop:
    image: bkimminich/juice-shop
    ports: ["3000:3000"]
```

```bash
docker compose up -d
```

---

## Usage

### Run Your First Scan

**Linux / macOS:**
```bash
python main.py \
  --url http://localhost/dvwa \
  --login-user admin \
  --login-pass password \
  --scan-type full
```

**Windows (Command Prompt):**
```cmd
python main.py --url http://localhost/dvwa --login-user admin --login-pass password --scan-type full
```

**Windows (PowerShell):**
```powershell
python main.py `
  --url http://localhost/dvwa `
  --login-user admin `
  --login-pass password `
  --scan-type full
```

The scanner will:
1. Log in to DVWA automatically
2. Crawl the site to find all pages and forms
3. Test everything it finds
4. Print colour-coded findings to your terminal
5. Save reports: `scan_report.md`, `scan_report.html`, `scan_report.json`, `scan_report.sarif`

Open `scan_report.html` in your browser for a readable report.

### Cheat Sheet

| What you want | Command |
|---------------|---------|
| Full scan (everything) | `python main.py --url http://localhost/dvwa --login-user admin --login-pass password` |
| SQL Injection only | `python main.py --url http://localhost/dvwa --scan-type sqli` |
| XSS only | `python main.py --url http://localhost/dvwa --scan-type xss` |
| Passive only (no payloads) | `python main.py --url http://localhost/dvwa --scan-type passive` |
| Custom report name | `python main.py --url http://localhost/dvwa --output reports/my_scan` |
| Verbose logging | `python main.py --url http://localhost/dvwa --verbose` |
| Through Burp Suite proxy | `python main.py --url http://localhost/dvwa --proxy http://127.0.0.1:8080` |
| JWT/API token auth | `python main.py --url http://api.example.com --auth-token eyJhbG...` |
| VirusTotal threat intel | `python main.py --url http://target.com --vt-api-key YOUR_KEY` |
| CVE lookup | `python main.py --url http://localhost/dvwa --nvd-api-key YOUR_KEY` |
| Self-signed HTTPS cert | `python main.py --url https://localhost:8443 --no-verify-ssl` |
| Slow polite scan | `python main.py --url http://localhost/dvwa --delay 2.0 --threads 1` |
| CI/CD — fail on High+ | `python main.py --url http://localhost/dvwa --fail-on high` |
| Use YAML config | `python main.py --config w3bsp1d3r.yaml` |
| Use config with profile | `python main.py --config w3bsp1d3r.yaml --profile thorough` |
| PDF + all report formats | `python main.py --url http://localhost/dvwa --formats html md json sarif pdf` |
| Compare with previous scan | `python main.py --url http://localhost/dvwa --compare-with previous_scan.json` |
| Start REST API server | `python main.py --api-server --api-port 8888` |
| Live dashboard | `python main.py --url http://localhost/dvwa --dashboard` |

### Streamlit GUI

```bash
pip install streamlit
streamlit run gui.py
```

---

## YAML Config Files

Instead of passing dozens of CLI flags, define your scan configuration in a YAML file. See [`w3bsp1d3r.example.yaml`](w3bsp1d3r.example.yaml) for the full annotated reference.

```bash
# Copy the example and customise
cp w3bsp1d3r.example.yaml w3bsp1d3r.yaml

# Run with a config file
python main.py --config w3bsp1d3r.yaml

# Override the profile from the command line
python main.py --config w3bsp1d3r.yaml --profile thorough
```

### Scan Profiles

The `--profile` flag selects a preset configuration tuned for different use cases:

| Profile | Threads | Delay | Max Pages | Use Case |
|---------|---------|-------|-----------|----------|
| **quick** | 2 | 0.2s | 10 | Fast smoke test, CI pipelines |
| **standard** | 4 | 0.5s | 50 | Default — balanced speed and coverage |
| **thorough** | 8 | 1.0s | 500 | Deep scan, full coverage, slower |
| **stealth** | 1 | 3.0s | 30 | Low-and-slow to avoid WAF/IDS detection |

CLI flags always take precedence over config file values, which take precedence over profile defaults.

### Environment variable references

Config values can reference environment variables using `${VAR_NAME}` syntax with optional defaults:

```yaml
auth:
  oauth2_client_id: ${W3BSP1D3R_OAUTH_CLIENT_ID}
  oauth2_client_secret: ${W3BSP1D3R_OAUTH_CLIENT_SECRET}

integrations:
  virustotal:
    api_key: ${W3BSP1D3R_VT_API_KEY:-}
```

---

## Enterprise Authentication

W3BSP1D3R v1.0.0 supports multiple authentication methods beyond simple form login.

### Form-based login (default)

```bash
python main.py --url http://localhost/dvwa --login-user admin --login-pass password
```

### Bearer / JWT token

```bash
python main.py --url http://api.example.com --auth-token eyJhbGciOiJIUzI1NiIs...
```

### OAuth2 Client Credentials

```bash
python main.py --url http://api.example.com \
  --auth-type oauth2 \
  --oauth2-token-url https://auth.example.com/oauth/token \
  --oauth2-client-id YOUR_CLIENT_ID \
  --oauth2-client-secret YOUR_CLIENT_SECRET \
  --oauth2-scope "read write"
```

### NTLM / Windows Authentication

Requires `pip install requests-ntlm`.

```bash
python main.py --url http://intranet.corp.local \
  --auth-type ntlm \
  --login-user admin \
  --login-pass password \
  --ntlm-domain CORP
```

### API Key Authentication

```bash
python main.py --url http://api.example.com \
  --auth-type apikey \
  --auth-token "sk-abc123..."
```

### Custom Header Authentication

```bash
python main.py --url http://api.example.com \
  --auth-type header \
  --auth-token "X-Custom-Auth: my-secret-token"
```

### YAML config for auth

All authentication methods can be configured in the YAML config file:

```yaml
auth:
  auth_type: oauth2
  oauth2_token_url: https://auth.example.com/oauth/token
  oauth2_client_id: ${W3BSP1D3R_OAUTH_CLIENT_ID}
  oauth2_client_secret: ${W3BSP1D3R_OAUTH_CLIENT_SECRET}
  oauth2_scope: "read write"
```

---

## Structured JSON Logging

For SIEM, ELK stack, Splunk, or any log aggregation platform, W3BSP1D3R can output structured JSON logs.

```bash
# JSON logs to file
python main.py --url http://localhost/dvwa \
  --log-format json \
  --log-file scan.log

# JSON logs to stdout (pipe to jq, Logstash, etc.)
python main.py --url http://localhost/dvwa --log-format json

# Verbose mode (DEBUG level)
python main.py --url http://localhost/dvwa \
  --log-format json \
  --verbose \
  --log-file scan.log
```

Each log entry is a single JSON object:

```json
{
  "timestamp": "2026-03-20T14:32:01.123Z",
  "level": "WARNING",
  "module": "sqli",
  "event": "finding_detected",
  "severity": "CRITICAL",
  "url": "http://localhost/dvwa/vulnerabilities/sqli/",
  "parameter": "id",
  "method": "GET"
}
```

Log levels: `WARNING` (default), `DEBUG` (with `--verbose`).

---

## Scan Scope Control

Use `--include` and `--exclude` glob patterns to control which URLs the crawler and testers will process.

```bash
# Only scan URLs under /dvwa/vulnerabilities/
python main.py --url http://localhost/dvwa \
  --include "http://localhost/dvwa/vulnerabilities/*"

# Exclude logout and setup pages
python main.py --url http://localhost/dvwa \
  --exclude "*/logout*" \
  --exclude "*/setup.php*"

# Combine both
python main.py --url http://localhost/dvwa \
  --include "http://localhost/dvwa/vulnerabilities/*" \
  --exclude "*/logout*"
```

Scope patterns also work in the YAML config:

```yaml
target:
  url: http://localhost/dvwa
  scope:
    include:
      - "http://localhost/dvwa/vulnerabilities/*"
    exclude:
      - "*/logout*"
      - "*/setup.php*"
```

---

## Finding Deduplication

W3BSP1D3R automatically deduplicates findings using SHA-256 fingerprints. Each finding is hashed based on its URL, parameter, vulnerability type, and payload category. If the same vulnerability is detected through multiple crawl paths, it appears only once in the report.

This is especially useful for:
- Large sites where multiple pages share the same vulnerable component
- Thorough scans with high `--max-pages` values
- Reducing noise in CI/CD pipelines

Deduplication is always on and requires no configuration.

---

## Checkpoint / Resume

Long-running scans can be interrupted by crashes, network failures, or system restarts. The checkpoint system saves scan progress to disk so you can resume where you left off.

```bash
# Enable checkpointing
python main.py --url http://localhost/dvwa \
  --checkpoint \
  --max-pages 500

# Resume an interrupted scan (auto-detected from checkpoint directory)
python main.py --url http://localhost/dvwa --checkpoint
```

Checkpoint files are stored in `.w3bsp1d3r/checkpoints/` by default. Completed scans automatically clean up their checkpoint files.

YAML config:

```yaml
checkpoint:
  enabled: true
  directory: .w3bsp1d3r/checkpoints
```

---

## Audit Trail

For compliance requirements (SOC 2, ISO 27001, PCI-DSS), W3BSP1D3R can write an immutable audit log of every scan action.

```bash
python main.py --url http://localhost/dvwa \
  --audit-log .w3bsp1d3r/audit.log
```

The audit log records:
- Scan start/stop timestamps
- Target URL and authentication method used
- Every test module executed
- Findings discovered (severity, type, URL)
- Configuration changes and overrides
- Operator identity (from OS username)

YAML config:

```yaml
audit:
  enabled: true
  log_file: .w3bsp1d3r/audit.log
```

---

## Historical Database

Track vulnerability trends over time with a local SQLite database that stores scan results across runs.

```bash
# Enable the database
python main.py --url http://localhost/dvwa \
  --database .w3bsp1d3r/scans.db

# Compare current scan against historical data (automatic when database is enabled)
```

The database enables:
- **Trend tracking** — see if vulnerabilities are being fixed or introduced over time
- **Regression detection** — alert when a previously-fixed vulnerability reappears
- **Metrics** — total findings by severity across all scans for a target

YAML config:

```yaml
database:
  enabled: true
  path: .w3bsp1d3r/scans.db
```

---

## Plugin System

Extend W3BSP1D3R with custom vulnerability testers without modifying core code.

```bash
# Load plugins from a directory
python main.py --url http://localhost/dvwa \
  --plugins-dir plugins/

# Load from multiple directories
python main.py --url http://localhost/dvwa \
  --plugins-dir plugins/ \
  --plugins-dir /opt/company-plugins/
```

### Writing a plugin

Create a Python file in your plugins directory that subclasses `BaseTester`:

```python
# plugins/my_custom_tester.py
from scanner.testers.base import BaseTester
from scanner.crawler import CrawledPage
from scanner.reporting.models import Finding

class MyCustomTester(BaseTester):
    """Check for a company-specific vulnerability."""

    def __init__(self):
        super().__init__(name="My Custom Tester")

    def run(self, pages: list[CrawledPage]) -> list[Finding]:
        for page in pages:
            # Your detection logic here
            # Use self._inject_form(), self._inject_get_param(), self._log_finding()
            pass
        return self.findings
```

Plugins are auto-discovered at startup. Any class that inherits from `BaseTester` is registered and included in `full` scans.

YAML config:

```yaml
plugins:
  enabled: true
  directories:
    - plugins
    - /opt/shared-plugins
```

---

## Report Formats

Every scan produces report files in your chosen formats:

| Format | File | Use Case |
|--------|------|----------|
| **Markdown** | `scan_report.md` | GitHub PRs, bug bounty submissions, `pandoc` to PDF |
| **HTML** | `scan_report.html` | Interactive, self-contained security-assessment document — risk verdict, severity charts, OWASP mapping, remediation roadmap, live filtering, light/dark themes, print-to-PDF |
| **JSON** | `scan_report.json` | CI/CD pipelines, SIEM ingestion, custom tooling |
| **SARIF** | `scan_report.sarif` | GitHub Code Scanning, VS Code SARIF Viewer, CI/CD security gates |
| **PDF** | `scan_report.pdf` | Executive summaries, client deliverables, offline sharing |

By default, scans produce HTML, Markdown, JSON, and SARIF. To include PDF or select specific formats:

```bash
# All 5 formats
python main.py --url http://localhost/dvwa --formats html md json sarif pdf

# PDF only
python main.py --url http://localhost/dvwa --formats pdf

# JSON + SARIF for CI/CD
python main.py --url http://localhost/dvwa --formats json sarif
```

> **Note:** PDF generation requires `fpdf2` (`pip install fpdf2`), which is included in `requirements.txt`.

### Interactive HTML report

The HTML report was rebuilt in v1.0.0 into a self-contained, client-ready security-assessment document. It ships as a single file with **no external assets**, so it works fully offline and prints cleanly to PDF straight from the browser. New capabilities:

- **Cover & executive summary** — a computed overall-risk verdict (Critical → No Significant Issues), a unique report reference (`WSR-…`), scan duration, and headline coverage stats.
- **Risk profile** — a severity-distribution donut and a CVSS-banded breakdown of findings.
- **OWASP Top 10 (2021) coverage** — every finding mapped to its category, grouped and counted for triage.
- **Prioritised remediation roadmap** — findings consolidated by issue type and ranked **P1…Pn** (by severity and instance count) so the highest-impact fixes come first.
- **Rich per-finding metadata** — severity, detection **confidence** (Certain / Firm / Tentative), **CWE**, **OWASP** category, **CVSS** band, and a stable fingerprint, alongside the PoC payload, response evidence, and remediation guidance.
- **Scope & methodology appendix** — scope, approach, coverage, limitations, and a severity-rating key.
- **Built-in triage tools** — light/dark **theme toggle** (remembered), **live text search**, **severity filters**, **collapsible findings**, **copy-payload** and **copy-permalink** buttons, a **back-to-top** control, and one-click **Print / Save-as-PDF**.
- **Theme-aware & print-ready** — legible in both light and dark, with a dedicated print stylesheet that renders a clean paper document. All interactivity is progressive enhancement, so the report is still fully readable with JavaScript disabled.

---

## Report Diff / Comparison

Compare the current scan against a previous scan to see what changed — new findings, resolved findings, and regressions.

```bash
python main.py --url http://localhost/dvwa \
  --compare-with previous_scan.json
```

The diff report shows:
- **New findings** — vulnerabilities not present in the baseline scan
- **Resolved findings** — vulnerabilities that were fixed since the baseline
- **Persistent findings** — vulnerabilities still present
- **Regressions** — previously resolved vulnerabilities that reappeared

This is particularly useful in CI/CD pipelines to catch newly introduced vulnerabilities:

```bash
# CI/CD example: fail only on new findings
python main.py --url http://staging.example.com \
  --compare-with last_known_good.json \
  --fail-on high
```

---

## REST API Server

Run W3BSP1D3R as a REST API server for remote scan management, integration with orchestration tools, or building custom dashboards.

```bash
# Start the API server
python main.py --api-server --api-port 8888

# With authentication (set API key via environment variable)
W3BSP1D3R_API_KEY="your-secret-key" python main.py --api-server --api-port 8888
```

> **Note:** The REST API server requires Flask (`pip install flask`).

### API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/v1/scans` | Start a new scan |
| `GET` | `/api/v1/scans` | List all scans |
| `GET` | `/api/v1/scans/{id}` | Get scan status and results |
| `GET` | `/api/v1/scans/{id}/findings` | Get findings for a scan |
| `GET` | `/api/v1/targets` | List all scanned targets |
| `GET` | `/api/v1/stats` | Database statistics |
| `GET` | `/api/v1/health` | Health check (no auth required) |

### Example: Start a scan via API

```bash
curl -X POST http://localhost:8888/api/v1/scans \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your-secret-key" \
  -d '{
    "url": "http://localhost/dvwa",
    "login_user": "admin",
    "login_pass": "password",
    "scan_type": "full"
  }'
```

### Example: Poll for results

```bash
curl http://localhost:8888/api/v1/scans/abc123 \
  -H "X-API-Key: your-secret-key"
```

---

## Webhook Notifications

Get notified when scans complete or critical findings are discovered. Supports Slack, Microsoft Teams, Discord, and arbitrary webhook URLs.

```bash
# Slack
python main.py --url http://localhost/dvwa \
  --slack-webhook https://hooks.slack.com/services/T00/B00/xxxx

# Microsoft Teams
python main.py --url http://localhost/dvwa \
  --teams-webhook https://outlook.office.com/webhook/xxxx

# Discord
python main.py --url http://localhost/dvwa \
  --discord-webhook https://discord.com/api/webhooks/xxxx/yyyy

# Custom webhook (receives JSON POST)
python main.py --url http://localhost/dvwa \
  --webhook-url https://your-server.com/hooks/w3bsp1d3r
```

Multiple webhooks can be combined in a single scan. Notifications include:
- Scan completion summary (total findings by severity)
- Critical/high findings as they are discovered (real-time)
- Scan failure alerts

---

## Rate Limit Dashboard

Monitor scan progress in real time with a live terminal dashboard.

```bash
python main.py --url http://localhost/dvwa --dashboard
```

The dashboard displays:
- Requests per second (current / average / peak)
- HTTP status code distribution
- Pages crawled vs. total discovered
- Active test module and progress
- Rate limit back-off events (429/503 responses)
- Finding count by severity (live updating)

The dashboard uses the Rich library and runs in your terminal alongside normal output.

---

## Concurrency

W3BSP1D3R runs its detection modules on a thread pool. Each worker thread uses
its own HTTP session (with a shared, lock-protected cookie jar so authenticated
state is preserved), so requests execute **truly in parallel** rather than being
serialised through a single connection.

```bash
# Increase concurrency for I/O-bound targets
python main.py --url http://localhost/dvwa --threads 16
```

Higher `--threads` improves throughput on large, high-latency targets. Keep the
value modest (and raise `--delay`) against production systems to stay polite.

### Safe Concurrent Scans (API multi-tenancy)

Each scan now carries fully isolated state — HTTP sessions, rate-limit counters,
cookie jars, and finding stores are per-scan rather than global. This means the
[REST API server](#rest-api-server) can run **multiple independent scans at the
same time** without one scan's cookies, rate limits, or findings leaking into
another. Concurrent scans against different targets stay cleanly separated.

> **Experimental:** an async (`httpx`) backend lives in
> `scanner/utils/http_async.py` but is **not yet wired into the CLI** — there is
> no `--async` flag. The threaded backend above is the supported path.

---

## JavaScript / SPA Scanning (`--render`)

Modern apps (React, Vue, Angular, Next.js, Svelte, …) build their DOM in the
browser, so a plain HTTP GET returns an almost-empty shell. With `--render`,
W3BSP1D3R loads each page in a **headless Chromium** browser, waits for the SPA
to hydrate, and crawls the *rendered* DOM — discovering JavaScript-generated
links and forms the static crawler cannot see. It also enables the
**DOM-based XSS** tester, which proves client-side script execution by firing
`alert()` from injected payloads in the URL fragment and query parameters.

```bash
# One-time setup (browser download, ~150 MB)
pip install playwright
playwright install chromium

# Render JavaScript content and run DOM-XSS testing
python main.py --url https://app.example.com --scan-type full --render

# DOM-XSS only
python main.py --url https://app.example.com --scan-type domxss --render
```

If Playwright is not installed, `--render` prints a warning and the scanner
transparently falls back to the static HTTP crawler — nothing breaks.

> **Note:** rendering is slower (one browser navigation per page/probe). Keep
> `--max-pages` modest and raise `--delay` against production targets.

---

## Interaction-Driven Crawling & API Fuzzing (`--interact`)

A rendered DOM only reveals what's already on screen. Many single-page apps
hide their most interesting attack surface — the REST/JSON endpoints — behind a
button click, a search box, or a form submission. `--interact` drives those
interactions for you.

With `--interact`, W3BSP1D3R:

- **Exercises the live app safely** — reveals and submits search boxes, fills
  forms with benign values, and clicks non-destructive controls within a bounded
  budget, so the app makes the `fetch`/XHR calls it would make for a real user
- **Enumerates SPA hash routes** — walks client-side `#/route` views instead of
  stopping at the app shell
- **Fuzzes the REST/JSON endpoints it uncovers** — injectable API endpoints
  observed during interaction are probed for injection flaws directly, not just
  the HTML forms a static crawler would find

```bash
# Interaction-driven scan of a single-page app (implies --render)
python main.py --url https://app.example.com --scan-type full --interact

# Bound the interaction budget on large/slow apps
python main.py --url https://app.example.com --interact --max-pages 30 --delay 1.0
```

`--interact` implies `--render`. Because it actively drives the live
application, use it **only against targets you are authorised to test**. Actions
are limited to safe, non-destructive controls, but you should still point it at
lab or staging environments rather than production wherever possible.

---

## Environment Variables

All configuration options can be set via environment variables. CLI flags and config file values take precedence.

| Variable | Description | Default |
|----------|-------------|---------|
| `W3BSP1D3R_URL` | Target URL | — |
| `W3BSP1D3R_SCAN_TYPE` | Scan type | `full` |
| `W3BSP1D3R_THREADS` | Concurrent threads | `4` |
| `W3BSP1D3R_DELAY` | Delay between requests (seconds) | `0.5` |
| `W3BSP1D3R_TIMEOUT` | Per-request timeout (seconds) | `10` |
| `W3BSP1D3R_OUTPUT` | Report base filename | `scan_report` |
| `W3BSP1D3R_VT_API_KEY` | VirusTotal API key | — |
| `W3BSP1D3R_NVD_API_KEY` | NVD API key | — |
| `W3BSP1D3R_PROXY` | HTTP/HTTPS/SOCKS5 proxy URL | — |
| `W3BSP1D3R_AUTH_TOKEN` | Bearer/JWT token | — |
| `W3BSP1D3R_LOGIN_USER` | Login username | — |
| `W3BSP1D3R_LOGIN_PASS` | Login password | — |
| `W3BSP1D3R_API_KEY` | REST API server authentication key | — |
| `W3BSP1D3R_FAIL_ON` | CI/CD failure threshold | — |

---

## CLI Reference

```
python main.py --url URL [options]

Required:
  --url URL                   Target base URL (http:// or https://)

Configuration:
  --config FILE               YAML configuration file (see w3bsp1d3r.example.yaml)
  --profile PROFILE           Scan profile: quick | standard | thorough | stealth

Authentication:
  --login-user USERNAME       Form-based login username
  --login-pass PASSWORD       Form-based login password
  --auth-token TOKEN          Bearer/JWT token (Authorization header)
  --auth-type TYPE            Auth method: form | bearer | oauth2 | ntlm | apikey | header
  --oauth2-token-url URL      OAuth2 token endpoint
  --oauth2-client-id ID       OAuth2 client ID
  --oauth2-client-secret SEC  OAuth2 client secret
  --oauth2-scope SCOPE        OAuth2 scope string
  --ntlm-domain DOMAIN        NTLM domain (Windows auth)

Scan Configuration:
  --scan-type TYPE            full | passive | sqli | xss | csrf | headers | files |
                              traversal | redirect | cmdi | cve | idor | waf | ssti |
                              cors | ssl | cookies | nosqli | subdomains | dirs |
                              methods | fingerprint | xxe | jwt | info | ratelimit |
                              clickjack | domxss  (default: full)
  --threads N                 Concurrent tester threads (default: 4)
  --max-pages N               Max pages to crawl (default: 50)
  --delay SECS                Delay between requests (default: 0.5)
  --timeout SECS              Per-request timeout (default: 10)
  --no-verify-ssl             Disable TLS verification
  --render                    Render pages in headless Chromium (JS/SPA crawling +
                              DOM-XSS). Requires playwright; falls back to static crawl
  --interact                  Drive safe, bounded SPA interactions to reveal and fuzz
                              hidden REST/JSON endpoints (implies --render)
  --include PATTERN           URL include pattern (glob, repeatable)
  --exclude PATTERN           URL exclude pattern (glob, repeatable)

Output:
  --output FILENAME           Report base filename, no extension (default: scan_report)
  --formats FMT [FMT ...]     Report formats: html md json sarif pdf (default: html md json sarif)
  --verbose                   Debug logging — shows every HTTP request
  --quiet                     Suppress banner/progress output (findings + summary still shown)
  --compare-with FILE         Compare results against a previous scan JSON file
  --dashboard                 Show live rate-limit and progress dashboard in terminal

Logging:
  --log-format FORMAT         Log output format: text | json (default: text)
  --log-file FILE             Write logs to file

Persistence:
  --checkpoint                Enable checkpoint/resume for crash recovery
  --resume                    Resume a previously interrupted scan (implies --checkpoint)
  --audit-log FILE            Write audit trail to file (for compliance)
  --database FILE             SQLite database for historical scan tracking

Integrations:
  --vt-api-key KEY            VirusTotal API key
  --vt-delay SECS             Delay between VT requests (default: 15)
  --nvd-api-key KEY           NIST NVD API key for CVE lookups
  --proxy URL                 HTTP/HTTPS/SOCKS5 proxy (e.g. http://127.0.0.1:8080)
  --fail-on SEVERITY          Exit code 2 if findings >= severity (critical|high|medium|low)

Notifications:
  --slack-webhook URL         Slack incoming webhook URL
  --teams-webhook URL         Microsoft Teams webhook URL
  --discord-webhook URL       Discord webhook URL
  --webhook-url URL           Custom webhook URL (JSON POST, repeatable)

API Server:
  --api-server                Start as REST API server instead of running a scan
  --api-host HOST             API server host (default: 127.0.0.1)
  --api-port PORT             API server port (default: 8888)
  --api-key KEY               API key required to call the server (repeatable)

Plugins:
  --plugins-dir DIR           Plugin directory (repeatable)
```

---

## Reading the Output

Findings are colour-coded in the terminal:

| Severity | Meaning | Examples |
|----------|---------|---------|
| **CRITICAL** | Full compromise likely | SQLi, command injection, .env exposed |
| **HIGH** | Significant risk | Stored XSS, path traversal, NoSQL injection |
| **MEDIUM** | Should fix before production | CSRF, missing CSP, CORS misconfiguration |
| **LOW** | Minor info leak | Missing minor headers, server version disclosure |

Each finding includes: **URL**, **parameter**, **HTTP method**, **exact payload**, **evidence** from the response, and **remediation** steps.

---

## SQLi Detection Methods

| Method | How It Works | Speed |
|--------|-------------|-------|
| **Error-based** | Injects syntax-breaking characters, looks for DB error strings (MySQL, MSSQL, Oracle, PostgreSQL, SQLite). Skips signatures already in baseline. | Fast |
| **UNION-based** | Injects `UNION SELECT` with a unique marker, checks if marker appears in response | Fast |
| **Boolean-blind** | Compares TRUE vs FALSE condition responses against a clean baseline. Requires both absolute (50B) AND percentage (15%) thresholds plus a recheck. | Medium |
| **Time-based blind** | Injects `SLEEP(5)` / `WAITFOR DELAY` / `pg_sleep(5)`, measures response time delta against baseline | Slow |

---

## Troubleshooting

### "python" or "python3" not found

| OS | Fix |
|----|-----|
| **Windows** | Reinstall Python from [python.org](https://www.python.org/downloads/) and check **"Add Python to PATH"** |
| **macOS** | `brew install python` or download from [python.org](https://www.python.org/downloads/) |
| **Linux (Debian/Ubuntu)** | `sudo apt install python3 python3-venv python3-pip` |
| **Linux (Arch)** | `sudo pacman -S python` |
| **Linux (Fedora)** | `sudo dnf install python3` |

### "No module named venv" (Linux)

```bash
sudo apt install python3-venv    # Debian / Ubuntu
```

### PowerShell script execution error (Windows)

```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

### "xcrun: error" (macOS)

```bash
xcode-select --install
```

### Port 80 already in use (Windows)

DVWA needs port 80, but Windows often has IIS or Skype using it. Use a different port:

```cmd
docker run --rm -d -p 8080:80 --name dvwa vulnerables/web-dvwa
python main.py --url http://localhost:8080/dvwa --login-user admin --login-pass password
```

### Scanner can't connect / timeout errors

- Make sure the target is running: open the URL in your browser first
- If using Docker, check `docker ps` to confirm the container is up
- If behind a corporate proxy, try `--proxy http://your-proxy:port`
- For self-signed HTTPS certs, add `--no-verify-ssl`

### Rich terminal colours look broken

- **Windows:** Use [Windows Terminal](https://aka.ms/terminal) instead of the old `cmd.exe` — it supports full colour
- **macOS / Linux:** Should work out of the box. If not, try `export TERM=xterm-256color`

---

## Project Structure

```
W3BSP1D3R/
├── main.py                          CLI entry point
├── gui.py                           Streamlit GUI
├── W3BSP1D3R.bat                    One-click Windows launcher (double-click to run)
├── W3BSP1D3R.sh                     One-click Linux/macOS launcher (./W3BSP1D3R.sh)
├── install.sh                       Adds W3BSP1D3R to Linux app menu
├── setup.sh                         Setup script (Linux / macOS)
├── setup.bat                        Setup script (Windows)
├── requirements.txt
├── pyproject.toml
├── w3bsp1d3r.example.yaml           Annotated YAML config reference
│
├── scanner/
│   ├── core.py                      Orchestrator: auth → crawl → test → report
│   ├── crawler.py                   BFS crawler: links, forms, GET params, sitemap, robots.txt
│   ├── auth.py                      DVWA + generic form-based auth
│   ├── auth_enterprise.py           OAuth2, NTLM, API key, custom header auth
│   ├── virustotal.py                VirusTotal API v3
│   ├── checkpoint.py                Checkpoint/resume for crash recovery
│   ├── audit.py                     Audit trail logging for compliance
│   ├── db.py                        Historical SQLite scan database
│   ├── plugins.py                   Plugin loader and registry
│   ├── api.py                       REST API server (Flask) with API key auth
│   ├── webhooks.py                  Slack / Teams / Discord / generic notifications
│   ├── scheduler.py                 Cron-based recurring scan scheduler
│   ├── payloads.py                  Custom payload loader (YAML/JSON)
│   │
│   ├── integrations/
│   │   ├── ticketing.py             Jira + ServiceNow ticket creation
│   │   └── email_notifier.py        SMTP email notifications
│   │
│   ├── testers/
│   │   ├── base.py                  BaseTester — template method pattern
│   │   ├── sqli.py                  SQL injection (4 methods) + JSON/API fuzzing
│   │   ├── xss.py                   Reflected + stored XSS
│   │   ├── dom_xss.py               Browser-verified DOM-based XSS
│   │   ├── csrf.py                  Token analysis
│   │   ├── cmdi.py                  Command injection (output + time-based)
│   │   ├── path_traversal.py        15+ encoding variants
│   │   ├── open_redirect.py         3xx + body reflection
│   │   ├── sensitive_files.py       60+ path probes
│   │   ├── dir_discovery.py         Directory / path discovery
│   │   ├── headers.py               Security header checks
│   │   ├── clickjacking.py          Framing / clickjacking protection
│   │   ├── http_methods.py          Dangerous HTTP method checks
│   │   ├── nosql_injection.py       MongoDB/CouchDB injection
│   │   ├── ssti.py                  Server-side template injection
│   │   ├── xxe.py                   XML external entity injection
│   │   ├── jwt_test.py              JWT weakness checks
│   │   ├── idor.py                  Insecure direct object references
│   │   ├── cors.py                  CORS misconfiguration
│   │   ├── ssl_tls.py              SSL/TLS configuration
│   │   ├── cookie_security.py       Cookie flags analysis
│   │   ├── info_disclosure.py       Information disclosure checks
│   │   ├── rate_limit.py            Rate-limiting checks
│   │   ├── waf.py                   WAF detection
│   │   ├── tech_fingerprint.py      Technology fingerprinting
│   │   ├── subdomain.py             Subdomain enumeration
│   │   └── cve.py                   NVD CVE lookup
│   │
│   ├── reporting/
│   │   ├── models.py                Finding + ScanSummary dataclasses
│   │   ├── markdown_report.py
│   │   ├── html_report.py
│   │   ├── json_report.py
│   │   ├── sarif_report.py          SARIF v2.1.0
│   │   ├── pdf_report.py            PDF generation (fpdf2)
│   │   └── diff_report.py           Scan comparison / diff engine
│   │
│   └── utils/
│       ├── http.py                  Per-scan isolated session, SSRF guard, retry, rate limiting
│       ├── http_async.py            Async HTTP client (httpx)
│       ├── renderer.py              Headless Chromium rendering + SPA interaction (Playwright)
│       ├── display.py               Rich terminal UI + rate limit dashboard
│       └── logging_config.py        Structured logging (text + JSON)
│
├── Dockerfile                       Multi-stage container build
├── docker-compose.yml               Scanner + API + DVWA + Juice Shop
├── .github/workflows/ci.yml         GitHub Actions CI (lint + test)
├── plugins/                         Custom plugin directory (user-created)
│
├── tests/                           140 unit tests
│   ├── test_baseline_error.py       Baseline FP suppression (SQLi, NoSQL, CMDi, PathTraversal)
│   ├── test_sqli_boolean.py         3-way boolean SQLi logic
│   ├── test_xss_reflected.py        Structural XSS verification
│   ├── test_crawler_xxe.py          XXE-safe XML parsing
│   ├── test_http_safety.py          SSRF guard + response size limit
│   ├── test_sensitive_files.py      .env detection
│   ├── test_accuracy.py             Accuracy harness (render, API fuzzing, SPA routes)
│   ├── test_isolation.py            Per-scan state isolation for concurrent scans
│   ├── test_enterprise.py           Config, checkpoint, audit, dedup, scope, metrics, webhooks, DB
│   └── test_enterprise_phase3.py    OWASP mapping, API auth, cron, payloads, ticketing, email
│
└── examples/
    └── dvwa_scan.sh
```

---

## Running Tests

**Linux / macOS:**
```bash
source venv/bin/activate
python -m pytest tests/ -v
```

**Windows:**
```cmd
venv\Scripts\activate
python -m pytest tests/ -v
```

```
140 passed
```

Tests cover: boolean SQLi logic, XSS structural verification, baseline false-positive suppression across all error-based testers, SSRF redirect blocking, XXE prevention, response size limits, sensitive file detection, finding deduplication, checkpoint serialisation, audit log formatting, plugin loading, config profile merging, report diff logic, JSON log output, OWASP Top 10 mapping, API key authentication (401/403/200), cron expression parsing, scan scheduling, custom payload loading, Jira/ServiceNow formatting, email notification rendering, webhook message building, per-scan state isolation for concurrent scans, and the accuracy harness (rendering, REST/JSON API fuzzing, and SPA route discovery).

---

## Extending the Scanner

### Option 1: Plugin directory (recommended)

Drop a Python file into your `plugins/` directory — see [Plugin System](#plugin-system) above.

### Option 2: Modify core (advanced)

Add a new vulnerability tester in 3 steps:

**1.** Create `scanner/testers/my_tester.py`:

```python
from scanner.testers.base import BaseTester
from scanner.crawler import CrawledPage
from scanner.reporting.models import Finding

class MyTester(BaseTester):
    def __init__(self):
        super().__init__(name="My Tester")

    def run(self, pages: list[CrawledPage]) -> list[Finding]:
        # Your detection logic here
        # Use self._inject_form(), self._inject_get_param(), self._log_finding()
        return self.findings
```

**2.** Register it in `scanner/core.py`:

```python
from scanner.testers.my_tester import MyTester

_TESTER_MAP["mytester"] = MyTester
```

**3.** Add `"mytester"` to the `--scan-type` choices in `main.py`.

---

## Dependencies

| Library | Purpose |
|---------|---------|
| [requests](https://github.com/psf/requests) | HTTP sessions, cookies, auth |
| [Beautiful Soup 4](https://www.crummy.com/software/BeautifulSoup/) | HTML parsing, form extraction |
| [lxml](https://lxml.de/) | Fast HTML/XML parser backend |
| [Rich](https://github.com/Textualize/rich) | Terminal colours, panels, progress bars, dashboard |
| [defusedxml](https://github.com/tiran/defusedxml) | XXE-safe XML parsing |
| [PyYAML](https://pyyaml.org/) | YAML config file parsing |
| [fpdf2](https://github.com/py-pdf/fpdf2) | PDF report generation |
| [httpx](https://www.python-httpx.org/) | Async HTTP client (optional — `pip install httpx`) |
| [Flask](https://flask.palletsprojects.com/) | REST API server (optional — `pip install flask`) |
| [requests-ntlm](https://github.com/requests/requests-ntlm) | NTLM/Windows auth (optional — `pip install requests-ntlm`) |
| [Streamlit](https://streamlit.io/) | GUI (optional — `pip install streamlit`) |

---

## Credits

### Lab Environments
- [DVWA](https://github.com/digininja/DVWA) — Ryan Dewhurst & contributors
- [OWASP Juice Shop](https://github.com/juice-shop/juice-shop) — Bjorn Kimminich & OWASP

### References
- [OWASP Top 10](https://owasp.org/Top10/)
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/)
- [VirusTotal API v3](https://docs.virustotal.com/reference/overview)
- [NIST NVD](https://nvd.nist.gov/)

---

## License

MIT License — see [LICENSE](LICENSE) for details.

**The author assumes no responsibility or liability for any misuse, damage, or legal consequences arising from the use of this software. By using W3BSP1D3R you acknowledge that you do so entirely at your own risk.**

---

*Built by S1YOL.*
