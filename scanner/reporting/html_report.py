from __future__ import annotations
"""
scanner/reporting/html_report.py
----------------------------------
Generates a self-contained, professional HTML vulnerability report.

Features:
  - Single-file output (CSS embedded in <style>) — no external dependencies
  - Dark spider-web themed design matching the W3BSP1D3R brand
  - Severity-coded colour scheme matching CVSS tiers
  - Collapsible finding cards for easy navigation
  - Summary statistics bar chart (pure CSS, no JavaScript required)
  - Print-friendly stylesheet
"""

import html
import logging
from pathlib import Path

from scanner.reporting.models import Finding, ScanSummary, Severity

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Severity → CSS class mapping
# ---------------------------------------------------------------------------
_SEV_CLASS = {
    Severity.CRITICAL: "critical",
    Severity.HIGH:     "high",
    Severity.MEDIUM:   "medium",
    Severity.LOW:      "low",
}


def write_html_report(summary: ScanSummary, output_path: str) -> Path:
    """
    Write a self-contained HTML vulnerability report.

    Args:
        summary     : Completed ScanSummary from the scanner.
        output_path : Destination .html file path.

    Returns:
        Path object of the written report.
    """
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    with path.open("w", encoding="utf-8") as fh:
        fh.write(_build_html(summary))

    logger.info("HTML report written to %s", path)
    return path


# ---------------------------------------------------------------------------
# HTML builder
# ---------------------------------------------------------------------------

def _build_html(summary: ScanSummary) -> str:
    findings = summary.sorted_findings()
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>W3BSP1D3R — {html.escape(summary.target_url)}</title>
{_CSS}
</head>
<body>
<div class="web-bg"></div>
{_build_header(summary)}
<main>
{_build_summary_section(summary)}
{_build_findings_section(findings)}
</main>
{_build_footer()}
</body>
</html>"""


def _build_header(summary: ScanSummary) -> str:
    return f"""
<header>
  <div class="header-inner">
    <div class="logo-section">
      <div class="logo-text">W<span class="accent">3</span>BSP<span class="accent">1</span>D<span class="accent">3</span>R</div>
      <div class="logo-sub">Web Vulnerability Scanner</div>
      <div class="version-badge">v3.0.0-beta</div>
    </div>
    <h1>Scan Report</h1>
    <div class="meta-grid">
      <div class="meta-item"><span class="label">Target</span><code>{html.escape(summary.target_url)}</code></div>
      <div class="meta-item"><span class="label">Scan Type</span>{html.escape(summary.scan_type)}</div>
      <div class="meta-item"><span class="label">Started</span>{html.escape(summary.started_at)}</div>
      <div class="meta-item"><span class="label">Finished</span>{html.escape(summary.finished_at)}</div>
    </div>
  </div>
  <div class="warning-banner">
    AUTHORISED TESTING ONLY — Scanning without authorization is a federal crime under the Computer Fraud and Abuse Act (CFAA, 18 U.S.C. &sect; 1030).
    Only use against systems you own or have explicit written permission to test.
    The author assumes no responsibility for misuse.
  </div>
</header>"""


def _build_summary_section(summary: ScanSummary) -> str:
    total = summary.total_findings or 1  # avoid division by zero in bar calc

    def bar(count: int, css_class: str) -> str:
        pct = min(int((count / total) * 100), 100)
        return (
            f'<div class="bar-row">'
            f'<span class="bar-label {css_class}">{css_class.upper()}</span>'
            f'<div class="bar-track"><div class="bar-fill {css_class}" style="width:{pct}%"></div></div>'
            f'<span class="bar-count {css_class}">{count}</span>'
            f'</div>'
        )

    return f"""
<section class="summary">
  <h2><span class="section-icon">&#x25C8;</span> Executive Summary</h2>
  <div class="stats-grid">
    <div class="stat-box"><div class="stat-num">{summary.pages_crawled}</div><div class="stat-label">Pages Crawled</div></div>
    <div class="stat-box"><div class="stat-num">{summary.forms_found}</div><div class="stat-label">Forms Found</div></div>
    <div class="stat-box"><div class="stat-num">{summary.params_tested}</div><div class="stat-label">Params Tested</div></div>
    <div class="stat-box highlight"><div class="stat-num">{summary.total_findings}</div><div class="stat-label">Total Findings</div></div>
  </div>
  <h3>Severity Breakdown</h3>
  <div class="bar-chart">
    {bar(summary.critical_count, 'critical')}
    {bar(summary.high_count,     'high')}
    {bar(summary.medium_count,   'medium')}
    {bar(summary.low_count,      'low')}
  </div>
</section>"""


def _build_findings_section(findings: list[Finding]) -> str:
    if not findings:
        return """
<section class="findings">
  <h2><span class="section-icon">&#x25C8;</span> Findings</h2>
  <p class="no-findings">No vulnerabilities detected during this scan.</p>
</section>"""

    cards = "\n".join(_build_finding_card(i + 1, f) for i, f in enumerate(findings))
    return f"""
<section class="findings">
  <h2><span class="section-icon">&#x25C8;</span> Findings <span class="count-badge">{len(findings)}</span></h2>
  {cards}
</section>"""


def _build_finding_card(idx: int, f: Finding) -> str:
    sev_class = _SEV_CLASS.get(f.severity, "low")
    return f"""
<details class="finding-card {sev_class}" open>
  <summary>
    <span class="finding-num">#{idx}</span>
    <span class="finding-title">{html.escape(f.vuln_type)}</span>
    <span class="sev-badge {sev_class}">{html.escape(f.severity)}</span>
  </summary>
  <div class="finding-body">
    <table class="meta-table">
      <tr><th>URL</th><td><code>{html.escape(f.url)}</code></td></tr>
      <tr><th>Parameter</th><td><code>{html.escape(f.parameter)}</code></td></tr>
      <tr><th>Method</th><td><code>{html.escape(f.method)}</code></td></tr>
      <tr><th>Timestamp</th><td>{html.escape(f.timestamp)}</td></tr>
    </table>
    <h4>Proof-of-Concept Payload</h4>
    <pre class="payload">{html.escape(f.payload)}</pre>
    <h4>Evidence</h4>
    <blockquote class="evidence">{html.escape(f.evidence)}</blockquote>
    <h4>Remediation</h4>
    <div class="remediation">{html.escape(f.remediation)}</div>
  </div>
</details>"""


def _build_footer() -> str:
    return """
<footer>
  <div class="footer-brand">W<span class="accent">3</span>BSP<span class="accent">1</span>D<span class="accent">3</span>R</div>
  <p>Generated by <strong>W3BSP1D3R</strong> v3.0.0-beta &mdash; by S1YOL</p>
  <p class="legal">This report is confidential. Unauthorised distribution may violate applicable law.</p>
</footer>"""


# ---------------------------------------------------------------------------
# Embedded CSS — dark spider-web themed design
# ---------------------------------------------------------------------------
_CSS = """<style>
:root {
  --critical: #ff2d2d;  --critical-bg: #3a0a0a;
  --high:     #ff6a00;  --high-bg:     #3a1f00;
  --medium:   #ffc107;  --medium-bg:   #3a3000;
  --low:      #00b0ff;  --low-bg:      #002a3a;
  --bg:       #0a0a0f;
  --surface:  #12121a;
  --card:     #16161f;
  --border:   #2a2a3a;
  --text:     #e0e0e8;
  --muted:    #8888a0;
  --accent:   #ff2d2d;
  --accent2:  #cc0000;
  --glow:     rgba(255, 45, 45, 0.15);
}
* { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: 'Segoe UI', system-ui, -apple-system, sans-serif; background: var(--bg);
       color: var(--text); line-height: 1.6; padding: 0; min-height: 100vh; position: relative; }
main { max-width: 960px; margin: 0 auto; padding: 0 2rem 2rem; }
a { color: var(--accent); }
code, pre { font-family: 'Cascadia Code', 'Fira Code', 'JetBrains Mono', 'Courier New', monospace; }
h1 { font-size: 1.6rem; margin-bottom: .5rem; color: var(--text); font-weight: 300;
     letter-spacing: .05em; }
h2 { font-size: 1.3rem; color: var(--accent); margin: 2.5rem 0 1rem;
     border-bottom: 1px solid var(--border); padding-bottom: .5rem;
     letter-spacing: .03em; font-weight: 600; }
h3 { font-size: 1rem; color: var(--muted); margin: 1.2rem 0 .5rem; font-weight: 500;
     text-transform: uppercase; letter-spacing: .08em; font-size: .85rem; }
h4 { font-size: .8rem; color: var(--muted); margin: 1rem 0 .25rem;
     text-transform: uppercase; letter-spacing: .08em; font-weight: 600; }
.section-icon { color: var(--accent); margin-right: .3rem; }

/* Spider web background pattern */
.web-bg { position: fixed; top: 0; left: 0; width: 100%; height: 100%;
          pointer-events: none; z-index: 0; opacity: .03;
          background-image:
            radial-gradient(circle at 20% 30%, var(--accent) 1px, transparent 1px),
            radial-gradient(circle at 80% 70%, var(--accent) 1px, transparent 1px),
            radial-gradient(circle at 50% 50%, var(--accent) 1px, transparent 1px);
          background-size: 120px 120px, 150px 150px, 80px 80px; }

/* Header */
header { background: linear-gradient(180deg, #0f0f18 0%, var(--bg) 100%);
         border-bottom: 1px solid var(--border); padding: 2rem 0 1.5rem;
         margin-bottom: 1.5rem; position: relative; z-index: 1; }
.header-inner { max-width: 960px; margin: 0 auto; padding: 0 2rem; }
.logo-section { margin-bottom: 1rem; }
.logo-text { font-size: 2.4rem; font-weight: 800; color: #ffffff;
             letter-spacing: .12em; font-family: 'Cascadia Code', 'Fira Code', monospace; }
.logo-text .accent { color: var(--accent); }
.logo-sub { font-size: .85rem; color: var(--muted); letter-spacing: .15em;
            text-transform: uppercase; margin-top: -.2rem; }
.version-badge { display: inline-block; background: var(--accent); color: #ffffff;
                 font-size: .7rem; font-weight: 700; padding: .15rem .5rem;
                 border-radius: 3px; margin-top: .5rem; letter-spacing: .06em;
                 font-family: monospace; }
.meta-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
             gap: .5rem; margin: 1rem 0; }
.meta-item { background: var(--surface); border: 1px solid var(--border);
             border-radius: 6px; padding: .6rem .85rem; }
.meta-item code { color: var(--accent); font-size: .85rem; }
.label { display: block; font-size: .65rem; color: var(--muted); text-transform: uppercase;
         letter-spacing: .08em; margin-bottom: .15rem; font-weight: 600; }
.warning-banner { max-width: 960px; margin: 1rem auto 0; padding: 0 2rem;
                  color: var(--muted); font-size: .75rem; font-style: italic;
                  border-left: 3px solid var(--accent2); padding-left: 1rem; }

/* Summary */
.summary { background: var(--surface); border: 1px solid var(--border);
           border-radius: 8px; padding: 1.5rem; margin-bottom: 2rem;
           box-shadow: 0 4px 20px rgba(0,0,0,.3); position: relative; z-index: 1; }
.stats-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: .75rem;
              margin-bottom: 1.5rem; }
.stat-box { text-align: center; background: var(--card); border: 1px solid var(--border);
            border-radius: 8px; padding: 1rem .5rem;
            transition: border-color .2s, box-shadow .2s; }
.stat-box:hover { border-color: var(--accent); box-shadow: 0 0 15px var(--glow); }
.stat-box.highlight { border: 2px solid var(--accent); box-shadow: 0 0 20px var(--glow); }
.stat-num { font-size: 2rem; font-weight: 700; color: #ffffff;
            font-family: 'Cascadia Code', monospace; }
.stat-box.highlight .stat-num { color: var(--accent); }
.stat-label { font-size: .7rem; color: var(--muted); text-transform: uppercase;
              letter-spacing: .06em; margin-top: .2rem; }

/* Bar chart */
.bar-chart { display: flex; flex-direction: column; gap: .5rem; }
.bar-row { display: grid; grid-template-columns: 80px 1fr 40px; gap: .75rem;
           align-items: center; }
.bar-label { font-size: .7rem; font-weight: 700; text-align: right;
             text-transform: uppercase; letter-spacing: .04em; }
.bar-track { background: var(--card); border-radius: 4px; height: 22px; overflow: hidden;
             border: 1px solid var(--border); }
.bar-fill { height: 100%; border-radius: 3px; transition: width .4s ease-out;
            box-shadow: 0 0 8px rgba(255,255,255,.1); }
.bar-count { font-size: .85rem; font-weight: 700; font-family: monospace; }
.bar-label.critical, .bar-count.critical { color: var(--critical); }
.bar-fill.critical { background: linear-gradient(90deg, var(--critical), #ff5555); }
.bar-label.high, .bar-count.high { color: var(--high); }
.bar-fill.high { background: linear-gradient(90deg, var(--high), #ff9933); }
.bar-label.medium, .bar-count.medium { color: var(--medium); }
.bar-fill.medium { background: linear-gradient(90deg, var(--medium), #ffe066); }
.bar-label.low, .bar-count.low { color: var(--low); }
.bar-fill.low { background: linear-gradient(90deg, var(--low), #66d9ff); }

/* Finding cards */
.findings { display: flex; flex-direction: column; gap: 1rem; position: relative; z-index: 1; }
.count-badge { background: var(--accent); color: #ffffff; font-size: .75rem;
               padding: .15rem .6rem; border-radius: 99px; margin-left: .5rem;
               font-weight: 700; letter-spacing: .03em; }
.no-findings { color: #22c55e; background: rgba(34, 197, 94, .08); border: 1px solid rgba(34, 197, 94, .2);
               border-radius: 6px; padding: 1rem; font-weight: 500; }
.finding-card { border-radius: 8px; overflow: hidden; border: 1px solid var(--border);
                box-shadow: 0 2px 10px rgba(0,0,0,.2);
                transition: box-shadow .2s, border-color .2s; }
.finding-card:hover { box-shadow: 0 4px 20px rgba(0,0,0,.4); }
.finding-card > summary { list-style: none; cursor: pointer; padding: .75rem 1rem;
                           display: flex; align-items: center; gap: .75rem;
                           font-weight: 600; user-select: none;
                           transition: background .2s; }
.finding-card > summary::-webkit-details-marker { display: none; }
.finding-card.critical > summary { background: var(--critical-bg); color: #ff8888;
                                    border-left: 4px solid var(--critical); }
.finding-card.high > summary { background: var(--high-bg); color: #ffaa66;
                                border-left: 4px solid var(--high); }
.finding-card.medium > summary { background: var(--medium-bg); color: #ffdd66;
                                  border-left: 4px solid var(--medium); }
.finding-card.low > summary { background: var(--low-bg); color: #66ccff;
                               border-left: 4px solid var(--low); }
.finding-num { font-size: .75rem; opacity: .6; font-family: monospace; }
.finding-title { flex: 1; }
.sev-badge { font-size: .7rem; font-weight: 700; padding: .2rem .6rem; border-radius: 3px;
             letter-spacing: .04em; }
.sev-badge.critical { background: var(--critical); color: white; }
.sev-badge.high     { background: var(--high);     color: white; }
.sev-badge.medium   { background: var(--medium);   color: #1a1a00; }
.sev-badge.low      { background: var(--low);      color: white; }
.finding-body { padding: 1.25rem; background: var(--card); border-top: 1px solid var(--border); }

.meta-table { width: 100%; border-collapse: collapse; margin-bottom: .75rem; font-size: .85rem; }
.meta-table th { width: 110px; text-align: left; color: var(--muted); padding: .3rem 0;
                 font-weight: 500; font-size: .8rem; text-transform: uppercase;
                 letter-spacing: .04em; }
.meta-table td code { background: var(--surface); border: 1px solid var(--border);
                       padding: .15rem .5rem; border-radius: 4px;
                       font-size: .8rem; word-break: break-all; color: var(--accent); }

.payload { background: rgba(255, 45, 45, .06); border-left: 3px solid var(--accent);
           padding: .75rem 1rem; border-radius: 0 6px 6px 0; font-size: .8rem;
           overflow-x: auto; white-space: pre-wrap; word-break: break-all;
           color: #ff8888; }

blockquote.evidence { border-left: 3px solid var(--border); padding: .5rem 1rem;
                      color: var(--muted); font-size: .85rem; font-style: italic;
                      margin: .5rem 0; background: rgba(255,255,255,.02);
                      border-radius: 0 4px 4px 0; }

.remediation { background: rgba(34, 197, 94, .06); border: 1px solid rgba(34, 197, 94, .15);
               border-left: 3px solid #22c55e; border-radius: 0 6px 6px 0;
               padding: .75rem 1rem; color: #88ddaa; font-size: .85rem; margin-top: .25rem; }

/* Footer */
footer { max-width: 960px; margin: 3rem auto 0; padding: 1.5rem 2rem;
         border-top: 1px solid var(--border); color: var(--muted); font-size: .75rem;
         position: relative; z-index: 1; }
.footer-brand { font-family: 'Cascadia Code', monospace; font-size: 1rem; font-weight: 700;
                color: #ffffff; margin-bottom: .3rem; letter-spacing: .08em; }
.footer-brand .accent { color: var(--accent); }
.legal { margin-top: .3rem; font-style: italic; opacity: .6; }

/* Responsive */
@media (max-width: 640px) {
  .stats-grid { grid-template-columns: repeat(2, 1fr); }
  .meta-grid { grid-template-columns: 1fr; }
  .logo-text { font-size: 1.8rem; }
  main { padding: 0 1rem 1rem; }
  .header-inner { padding: 0 1rem; }
}

@media print {
  :root {
    --bg: #ffffff; --surface: #f5f5f5; --card: #fafafa; --border: #e0e0e0;
    --text: #111111; --muted: #666666;
  }
  body { background: white; color: black; }
  .web-bg { display: none; }
  header { background: white; }
  .logo-text { color: #111; }
  .finding-card > summary { color: black !important; }
  .finding-body { background: white !important; }
  .stat-num { color: #111; }
  .remediation { color: #166534; }
  .payload { color: #991b1b; }
}
</style>"""
