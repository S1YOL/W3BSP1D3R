# W3BSP1D3R v1.0.0

First official release. W3BSP1D3R is a web vulnerability scanner written in Python — it crawls a target, maps every form and URL parameter, throws attack payloads at each one, and tells you what broke, with the exact payload that triggered it and how to fix it. 26 test modules, 5 report formats, and it now handles JavaScript-heavy sites and JSON APIs, not just static HTML.

Built for labs, authorised pentests, and CI pipelines.

**Only scan things you're allowed to scan** — systems you have written permission for, or deliberately vulnerable labs like DVWA, Juice Shop, HackTheBox, and TryHackMe. Everything you do with this is on you.

## What's new since the beta

The big change is that the scanner is no longer blind to modern single-page apps. Before, if your target rendered its pages with JavaScript, the crawler saw an empty shell and missed most of the attack surface. That's fixed:

- **`--render`** loads each page in headless Chromium and crawls the actual rendered DOM, so JS-generated links and forms get picked up.
- **`--interact`** goes a step further and drives the app — submits searches, fills forms with harmless values, clicks safe controls — so the XHR/fetch calls fire and the hidden REST/JSON endpoints behind them get discovered.
- **DOM-based XSS** is now detected and confirmed in the browser — it injects into the URL fragment and query params and only reports a hit if it actually fires `alert()`.
- **Hash routes** (`#/dashboard`, `#/users/1`) are enumerated, so SPA views get crawled instead of just the landing shell.
- **JSON API endpoints** found during a scan get fuzzed for injection directly, not treated as plain HTML.

Alongside that, the HTML report was rebuilt from scratch. It now opens with an overall risk verdict and a severity breakdown, maps each finding to the OWASP Top 10, gives you a prioritised list of what to fix first, and includes CWE/CVSS/confidence per finding. There's live search and severity filtering, a light/dark toggle, and it prints cleanly to PDF straight from the browser.

Two smaller but useful additions:

- The API server can now run **several scans at once** without them stepping on each other's state.
- **`--quiet`** strips the banner and progress bars so CI logs stay readable — you still get findings and the summary.

## What it checks for

26 modules across five areas:

- **Injection** — SQLi (error, UNION, boolean-blind, time-blind), NoSQL, command injection, SSTI, XXE
- **Client-side** — reflected XSS, stored XSS, DOM XSS, CSRF, open redirect, clickjacking
- **Access control** — path traversal, IDOR, weak JWTs, exposed sensitive files (`.env`, `.git/`, backups, admin panels), directory discovery
- **Config** — security headers, cookie flags, CORS, SSL/TLS, WAF detection, allowed HTTP methods, rate limiting
- **Recon** — subdomain enumeration, tech fingerprinting, information disclosure, CVE lookup against the NVD, VirusTotal lookups

It tries hard not to cry wolf: it pulls a clean baseline before injecting, requires boolean SQLi to pass a three-way check, confirms XSS payloads actually survived encoding in the response, and matches command-injection output by pattern rather than a loose substring.

## Getting started

```bash
git clone https://github.com/S1YOL/W3BSP1D3R.git
cd W3BSP1D3R
```

You need Python 3.10 or newer. Docker is optional and only matters if you want to spin up DVWA or Juice Shop to test against.

On Windows, double-click `W3BSP1D3R.bat`. On Linux/macOS, run `./W3BSP1D3R.sh`. Both set up a virtualenv, install dependencies, and drop you into a menu on first run. If you'd rather drive it yourself:

```bash
python main.py https://target.example.com                 # full scan
python main.py https://spa.example.com --render --interact # JS app with interaction
python main.py https://target.example.com --quiet          # for CI
python main.py --help                                       # everything else
```

## Other features worth knowing about

YAML config profiles, enterprise auth (OAuth2, NTLM, API key, custom headers), structured JSON logging for SIEM/ELK, scan scope include/exclude, checkpoint and resume for long runs, an audit trail, a SQLite history database for trend tracking, a plugin system for custom testers, PDF/JSON/Markdown/SARIF/HTML reports, report diffing, a REST API server with key auth, webhook alerts (Slack/Teams/Discord), Jira and ServiceNow ticket creation, email reports, a cron scheduler, and Docker/compose files.

---

140 tests passing · MIT license · by S1YOL
