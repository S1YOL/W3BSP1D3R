from __future__ import annotations
"""
scanner/reporting/html_report.py
----------------------------------
Generates a self-contained, professional HTML vulnerability report.

Design goals:
  - Single-file output (all CSS + JS inline) — no external deps, CSP-safe
  - Reads like a real security-assessment document, not a dashboard
  - Semantic severity colour system (colour always encodes risk)
  - Executive summary with computed overall-risk verdict + OWASP coverage
  - Prioritised remediation roadmap and a scope/methodology appendix
  - Interactive triage: theme toggle, live search + severity filters,
    collapsible findings, copy-to-clipboard, print/PDF — all optional
    (the report degrades gracefully with JavaScript disabled)
"""

import hashlib
import html
import logging
from collections import Counter
from datetime import datetime
from pathlib import Path

from scanner.reporting.models import Finding, ScanSummary, Severity

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Severity → CSS class / ordering
# ---------------------------------------------------------------------------
_SEV_CLASS = {
    Severity.CRITICAL: "critical",
    Severity.HIGH:     "high",
    Severity.MEDIUM:   "medium",
    Severity.LOW:      "low",
}
_SEV_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]

_SEV_DESC = {
    Severity.CRITICAL: "Remotely exploitable with severe impact (e.g. data loss "
                       "or code execution). Requires immediate remediation.",
    Severity.HIGH:     "Significant impact and likely exploitable. Warrants prompt "
                       "remediation.",
    Severity.MEDIUM:   "Moderate impact; exploitability is context-dependent. "
                       "Plan remediation.",
    Severity.LOW:      "Minimal impact or difficult to exploit in practice. "
                       "Address on a best-effort basis.",
}


def write_html_report(summary: ScanSummary, output_path: str) -> Path:
    """Write a self-contained HTML vulnerability report and return its Path."""
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as fh:
        fh.write(_build_html(summary))
    logger.info("HTML report written to %s", path)
    return path


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------

def _esc(value) -> str:
    return html.escape(str(value)) if value is not None else ""


def _fmt_ts(value: str) -> str:
    if not value:
        return "—"
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return dt.strftime("%Y-%m-%d %H:%M:%S UTC") if dt.tzinfo is None \
            else dt.strftime("%Y-%m-%d %H:%M:%S %Z")
    except (ValueError, TypeError):
        return _esc(value)


def _duration(started: str, finished: str) -> str | None:
    try:
        a = datetime.fromisoformat(started.replace("Z", "+00:00"))
        b = datetime.fromisoformat(finished.replace("Z", "+00:00"))
        secs = int((b - a).total_seconds())
        if secs < 0:
            return None
        h, rem = divmod(secs, 3600)
        m, s = divmod(rem, 60)
        if h:
            return f"{h}h {m}m {s}s"
        if m:
            return f"{m}m {s}s"
        return f"{s}s"
    except (ValueError, TypeError):
        return None


def _report_ref(summary: ScanSummary) -> str:
    try:
        dt = datetime.fromisoformat(summary.started_at.replace("Z", "+00:00"))
        stamp = dt.strftime("%Y%m%d")
    except (ValueError, TypeError):
        stamp = datetime.utcnow().strftime("%Y%m%d")
    tail = hashlib.sha1(summary.target_url.encode()).hexdigest()[:5].upper()
    return f"WSR-{stamp}-{tail}"


def _overall_risk(summary: ScanSummary) -> tuple[str, str, str]:
    if summary.critical_count:
        return ("Critical Risk", "critical",
                "Critical, remotely exploitable weaknesses were identified. "
                "Immediate remediation is strongly advised.")
    if summary.high_count:
        return ("High Risk", "high",
                "High-impact vulnerabilities were identified that are likely "
                "exploitable and warrant prompt remediation.")
    if summary.medium_count:
        return ("Medium Risk", "medium",
                "Moderate-severity issues were identified. Exploitability is "
                "context-dependent; remediation is recommended.")
    if summary.low_count:
        return ("Low Risk", "low",
                "Only low-severity or informational issues were identified. "
                "Residual risk is limited.")
    return ("No Significant Issues", "none",
            "No vulnerabilities were detected by this automated assessment. "
            "This does not guarantee the absence of all risk.")


# ---------------------------------------------------------------------------
# Document assembly
# ---------------------------------------------------------------------------

def _build_html(summary: ScanSummary) -> str:
    findings = summary.sorted_findings()
    return f"""<!DOCTYPE html>
<html lang="en" data-report>
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>W3BSP1D3R — Security Assessment · {_esc(summary.target_url)}</title>
{_CSS}
</head>
<body>
{_render_body(summary, findings)}
{_JS}
</body>
</html>"""


def _render_body(summary: ScanSummary, findings: list[Finding]) -> str:
    return f"""{_toolbar(summary)}
{_cover(summary, findings)}
<main class="doc">
{_contents(findings)}
{_exec_summary(summary, findings)}
{_risk_profile(summary)}
{_owasp_section(findings)}
{_roadmap_section(findings)}
{_findings_section(findings)}
{_methodology(summary)}
{_footer(summary)}
</main>
<button id="toTop" class="to-top" aria-label="Back to top" title="Back to top">&#8593;</button>"""


# ---------------------------------------------------------------------------
# Sticky toolbar
# ---------------------------------------------------------------------------

def _toolbar(summary: ScanSummary) -> str:
    return f"""
<div class="toolbar" role="toolbar" aria-label="Report actions">
  <div class="tb-inner">
    <span class="tb-brand">W<i>3</i>BSP<i>1</i>D<i>3</i>R</span>
    <span class="tb-ref">{_esc(_report_ref(summary))}</span>
    <div class="tb-actions">
      <button id="themeToggle" class="tb-btn" type="button" aria-label="Toggle colour theme">
        <span class="tb-ico">&#9681;</span><span class="tb-txt">Theme</span>
      </button>
      <button id="printBtn" class="tb-btn" type="button" aria-label="Print or save as PDF">
        <span class="tb-ico">&#8681;</span><span class="tb-txt">Print / PDF</span>
      </button>
    </div>
  </div>
</div>"""


# ---------------------------------------------------------------------------
# Cover
# ---------------------------------------------------------------------------

def _cover(summary: ScanSummary, findings: list[Finding]) -> str:
    label, sev_class, verdict = _overall_risk(summary)
    ref = _report_ref(summary)
    dur = _duration(summary.started_at, summary.finished_at)
    dur_row = f'<div><dt>Duration</dt><dd>{_esc(dur)}</dd></div>' if dur else ""
    return f"""
<header class="cover">
  {_WEB_SVG}
  <div class="cover-inner">
    <div class="cover-top">
      <div class="brand">
        <span class="brand-mark">W<i>3</i>BSP<i>1</i>D<i>3</i>R</span>
        <span class="brand-sub">Web Vulnerability Scanner</span>
      </div>
      <div class="cover-ref">
        <span class="ref-label">Report Ref.</span>
        <span class="ref-val">{_esc(ref)}</span>
      </div>
    </div>

    <div class="cover-title">
      <p class="eyebrow">Web Application Security Assessment</p>
      <h1>Vulnerability Scan Report</h1>
      <p class="cover-target"><span>Target</span><code>{_esc(summary.target_url)}</code></p>
    </div>

    <div class="verdict verdict-{sev_class}">
      <div class="verdict-badge">
        <span class="verdict-kicker">Overall Risk</span>
        <span class="verdict-label">{_esc(label)}</span>
      </div>
      <p class="verdict-text">{_esc(verdict)}</p>
    </div>

    <dl class="cover-meta">
      <div><dt>Assessment</dt><dd>{_esc(summary.scan_type)}</dd></div>
      <div><dt>Started</dt><dd>{_fmt_ts(summary.started_at)}</dd></div>
      <div><dt>Completed</dt><dd>{_fmt_ts(summary.finished_at)}</dd></div>
      {dur_row}
    </dl>
  </div>
  <p class="confidential">Confidential — Prepared for the system owner. Authorised distribution only.</p>
</header>"""


# ---------------------------------------------------------------------------
# Table of contents
# ---------------------------------------------------------------------------

def _contents(findings: list[Finding]) -> str:
    items = [
        ("#exec", "01", "Executive Summary"),
        ("#risk", "02", "Risk Profile"),
        ("#owasp", "03", "OWASP Top 10 Coverage"),
        ("#roadmap", "04", "Remediation Roadmap"),
        ("#findings", "05", f"Detailed Findings ({len(findings)})"),
        ("#scope", "A", "Scope & Methodology"),
    ]
    rows = "\n".join(
        f'<a class="toc-row" href="{href}"><span class="toc-num">{num}</span>'
        f'<span class="toc-name">{name}</span><span class="toc-dots"></span></a>'
        for href, num, name in items
    )
    return f"""
<nav class="toc" aria-label="Contents">
  <h2 class="toc-head">Contents</h2>
  {rows}
</nav>"""


# ---------------------------------------------------------------------------
# 01 — Executive summary
# ---------------------------------------------------------------------------

def _exec_summary(summary: ScanSummary, findings: list[Finding]) -> str:
    _, sev_class, verdict = _overall_risk(summary)

    def stat(num, label):
        return (f'<div class="stat"><div class="stat-num">{num}</div>'
                f'<div class="stat-label">{label}</div></div>')

    def sev_tile(count, name, cls):
        return (f'<div class="sev-tile sev-{cls}">'
                f'<span class="sev-dot"></span>'
                f'<span class="sev-count">{count}</span>'
                f'<span class="sev-name">{name}</span></div>')

    if findings:
        lead = (f"This automated assessment of "
                f"<code>{_esc(summary.target_url)}</code> examined "
                f"{summary.pages_crawled} page(s) and {summary.forms_found} form(s), "
                f"exercising {summary.params_tested} parameter(s). "
                f"It recorded <strong>{summary.total_findings} finding(s)</strong>. "
                f"{_esc(verdict)}")
    else:
        lead = (f"This automated assessment of "
                f"<code>{_esc(summary.target_url)}</code> examined "
                f"{summary.pages_crawled} page(s) and {summary.forms_found} form(s), "
                f"exercising {summary.params_tested} parameter(s), and recorded no "
                f"findings. {_esc(verdict)}")

    return f"""
<section id="exec" class="sec">
  <div class="sec-head"><span class="sec-num">01</span><h2>Executive Summary</h2></div>
  <p class="lead lead-{sev_class}">{lead}</p>

  <div class="stat-row">
    {stat(summary.pages_crawled, "Pages Crawled")}
    {stat(summary.forms_found, "Forms Discovered")}
    {stat(summary.params_tested, "Parameters Tested")}
    {stat(summary.total_findings, "Total Findings")}
  </div>

  <div class="sev-tiles">
    {sev_tile(summary.critical_count, "Critical", "critical")}
    {sev_tile(summary.high_count, "High", "high")}
    {sev_tile(summary.medium_count, "Medium", "medium")}
    {sev_tile(summary.low_count, "Low", "low")}
  </div>
</section>"""


# ---------------------------------------------------------------------------
# 02 — Risk profile (donut + distribution)
# ---------------------------------------------------------------------------

def _risk_profile(summary: ScanSummary) -> str:
    counts = [
        (summary.critical_count, "critical", "Critical"),
        (summary.high_count, "high", "High"),
        (summary.medium_count, "medium", "Medium"),
        (summary.low_count, "low", "Low"),
    ]
    total = summary.total_findings

    if total > 0:
        stops, acc = [], 0.0
        for count, cls, _name in counts:
            if count <= 0:
                continue
            start = acc / total * 100
            acc += count
            end = acc / total * 100
            stops.append(f"var(--sev-{cls}) {start:.3f}% {end:.3f}%")
        gradient = ", ".join(stops)
        center_sub = "finding" if total == 1 else "findings"
    else:
        gradient = "var(--ring-empty) 0% 100%"
        center_sub = "findings"

    legend_rows = ""
    for count, cls, name in counts:
        pct = (count / total * 100) if total else 0
        cvss = Severity.CVSS_RANGES.get(name, "—")
        legend_rows += (
            f'<tr class="lg-{cls}"><td class="lg-name"><span class="lg-dot"></span>{name}</td>'
            f'<td class="lg-cvss">{cvss}</td>'
            f'<td class="lg-bar"><span class="lg-track"><span class="lg-fill" '
            f'style="width:{pct:.1f}%"></span></span></td>'
            f'<td class="lg-count">{count}</td></tr>'
        )

    return f"""
<section id="risk" class="sec">
  <div class="sec-head"><span class="sec-num">02</span><h2>Risk Profile</h2></div>
  <div class="risk-grid">
    <figure class="donut" style="--donut: {gradient};">
      <div class="donut-hole">
        <span class="donut-total">{total}</span>
        <span class="donut-sub">{center_sub}</span>
      </div>
    </figure>
    <table class="legend">
      <thead><tr><th>Severity</th><th>CVSS v3.1</th><th>Distribution</th><th>Count</th></tr></thead>
      <tbody>
        {legend_rows}
      </tbody>
    </table>
  </div>
</section>"""


# ---------------------------------------------------------------------------
# 03 — OWASP coverage
# ---------------------------------------------------------------------------

def _owasp_section(findings: list[Finding]) -> str:
    buckets: dict[str, dict] = {}
    for f in findings:
        cat = f.owasp_category
        if not cat:
            key, cid, name = "uncat", "—", "Uncategorised"
        else:
            key, cid, name = cat["id"], cat["id"], cat["name"]
        b = buckets.setdefault(key, {"id": cid, "name": name, "n": 0, "sev": Counter()})
        b["n"] += 1
        b["sev"][f.severity] += 1

    if not buckets:
        body = '<p class="empty-note">No categorised findings to map.</p>'
    else:
        ordered = sorted(buckets.values(), key=lambda b: (b["id"] == "—", b["id"]))
        rows = ""
        for b in ordered:
            chips = "".join(
                f'<span class="mini-chip sev-{_SEV_CLASS[s]}">{b["sev"][s]} {s}</span>'
                for s in _SEV_ORDER if b["sev"].get(s)
            )
            rows += (
                f'<tr><td class="ow-id">{_esc(b["id"])}</td>'
                f'<td class="ow-name">{_esc(b["name"])}</td>'
                f'<td class="ow-chips">{chips}</td>'
                f'<td class="ow-n">{b["n"]}</td></tr>'
            )
        body = f"""<table class="owasp-table">
      <thead><tr><th>Category</th><th>Name</th><th>Findings by severity</th><th>Total</th></tr></thead>
      <tbody>{rows}</tbody>
    </table>"""

    return f"""
<section id="owasp" class="sec">
  <div class="sec-head"><span class="sec-num">03</span><h2>OWASP Top 10 (2021) Coverage</h2></div>
  <p class="sec-intro">Findings mapped to the OWASP Top 10 risk categories to aid triage and prioritisation.</p>
  {body}
</section>"""


# ---------------------------------------------------------------------------
# 04 — Remediation roadmap
# ---------------------------------------------------------------------------

def _roadmap_section(findings: list[Finding]) -> str:
    if not findings:
        return """
<section id="roadmap" class="sec">
  <div class="sec-head"><span class="sec-num">04</span><h2>Remediation Roadmap</h2></div>
  <p class="sec-intro">No remediation actions are required — no findings were recorded.</p>
</section>"""

    # Group by vulnerability type; keep the most severe instance's details.
    groups: dict[str, dict] = {}
    for f in findings:
        g = groups.get(f.vuln_type)
        order = Severity.ORDER.get(f.severity, 99)
        if g is None:
            groups[f.vuln_type] = {
                "type": f.vuln_type, "severity": f.severity, "order": order,
                "remediation": f.remediation, "cwe": f.cwe or "—",
                "locations": {(f.url, f.parameter)},
            }
        else:
            g["locations"].add((f.url, f.parameter))
            if order < g["order"]:
                g["order"] = order
                g["severity"] = f.severity
                g["remediation"] = f.remediation
                g["cwe"] = f.cwe or "—"

    ordered = sorted(groups.values(), key=lambda g: (g["order"], -len(g["locations"])))

    rows = ""
    for i, g in enumerate(ordered, start=1):
        cls = _SEV_CLASS.get(g["severity"], "low")
        n = len(g["locations"])
        inst = f"{n} location" + ("s" if n != 1 else "")
        rows += (
            f'<tr class="rm-row">'
            f'<td class="rm-pri"><span class="pri-badge sev-{cls}">P{i}</span></td>'
            f'<td class="rm-issue"><span class="rm-type">{_esc(g["type"])}</span>'
            f'<span class="rm-cwe">{_esc(g["cwe"])}</span></td>'
            f'<td class="rm-sev"><span class="pill sev-{cls}">{_esc(g["severity"])}</span></td>'
            f'<td class="rm-inst">{inst}</td>'
            f'<td class="rm-action">{_esc(g["remediation"])}</td>'
            f'</tr>'
        )

    return f"""
<section id="roadmap" class="sec">
  <div class="sec-head"><span class="sec-num">04</span><h2>Remediation Roadmap</h2>
    <span class="sec-count">{len(ordered)}</span></div>
  <p class="sec-intro">Recommended actions consolidated by issue type and ordered by priority
    (P1 = highest). Fixing the top of this list first yields the greatest risk reduction.</p>
  <div class="table-wrap">
    <table class="roadmap-table">
      <thead><tr><th>Priority</th><th>Issue</th><th>Severity</th><th>Affected</th><th>Recommended action</th></tr></thead>
      <tbody>{rows}</tbody>
    </table>
  </div>
</section>"""


# ---------------------------------------------------------------------------
# 05 — Findings
# ---------------------------------------------------------------------------

def _findings_section(findings: list[Finding]) -> str:
    if not findings:
        return """
<section id="findings" class="sec">
  <div class="sec-head"><span class="sec-num">05</span><h2>Detailed Findings</h2></div>
  <div class="clean-state">
    <span class="clean-check">&#10003;</span>
    <div>
      <strong>No vulnerabilities were detected.</strong>
      <p>The automated checks completed without recording any findings. Consider a manual
      review for logic-level issues that automated scanning cannot cover.</p>
    </div>
  </div>
</section>"""

    total = len(findings)

    def chip(count, name, cls):
        return (f'<button class="filter-chip sev-{cls}" type="button" data-sev="{cls}" '
                f'aria-pressed="true"><span class="chip-dot"></span>{name}'
                f'<span class="chip-n">{count}</span></button>')

    counts = Counter(f.severity for f in findings)
    controls = f"""
  <div class="filter-bar" role="region" aria-label="Filter findings">
    <div class="filter-search">
      <span class="fs-ico" aria-hidden="true">&#9906;</span>
      <input id="findSearch" class="find-search" type="search"
             placeholder="Filter by type, URL, parameter, or CWE&hellip;" aria-label="Filter findings by text">
    </div>
    <div class="filter-chips">
      {chip(counts.get(Severity.CRITICAL, 0), "Critical", "critical")}
      {chip(counts.get(Severity.HIGH, 0), "High", "high")}
      {chip(counts.get(Severity.MEDIUM, 0), "Medium", "medium")}
      {chip(counts.get(Severity.LOW, 0), "Low", "low")}
    </div>
    <div class="filter-tools">
      <span class="filter-count">Showing <span id="filterCount">{total} of {total}</span></span>
      <button id="expandAll" class="mini-btn" type="button">Expand all</button>
      <button id="collapseAll" class="mini-btn" type="button">Collapse all</button>
    </div>
  </div>
  <p id="noMatch" class="no-match" hidden>No findings match the current filters.</p>"""

    cards = "\n".join(_finding(i + 1, f) for i, f in enumerate(findings))
    return f"""
<section id="findings" class="sec">
  <div class="sec-head"><span class="sec-num">05</span><h2>Detailed Findings</h2>
    <span class="sec-count">{total}</span></div>
  {controls}
  <div class="findings-list">
  {cards}
  </div>
</section>"""


def _finding(idx: int, f: Finding) -> str:
    sev_class = _SEV_CLASS.get(f.severity, "low")
    ref = f"F-{idx:02d}"
    cwe = f.cwe or "—"
    owasp = f.owasp_category
    owasp_str = f'{owasp["id"]} · {owasp["name"]}' if owasp else "—"
    cvss = Severity.CVSS_RANGES.get(f.severity, "—")
    conf = f.confidence or "—"

    def meta(label, value, mono=False):
        cls = "mono" if mono else ""
        return (f'<div class="mrow"><dt>{label}</dt>'
                f'<dd class="{cls}">{value}</dd></div>')

    evidence = _esc(f.evidence) or "<span class='muted'>No response evidence captured.</span>"

    # Searchable text blob (attribute-escaped) for client-side filtering.
    blob = _esc(" ".join(str(x) for x in (
        f.vuln_type, f.url, f.parameter, f.method, cwe, owasp_str, f.severity
    )).lower())

    return f"""
<article id="finding-{idx}" class="finding sev-border-{sev_class}"
         data-sev="{sev_class}" data-text="{blob}">
  <header class="f-head">
    <button class="f-head-btn" type="button" aria-expanded="true" aria-controls="fbody-{idx}">
      <span class="f-ref">{ref}</span>
      <span class="f-title">{_esc(f.vuln_type)}</span>
      <span class="pill sev-{sev_class}">{_esc(f.severity)}</span>
      <span class="caret" aria-hidden="true"></span>
    </button>
    <button class="icon-btn" type="button" data-copy="link" data-target="finding-{idx}"
            title="Copy link to this finding" aria-label="Copy link to this finding">#</button>
  </header>

  <div class="f-body" id="fbody-{idx}">
    <div class="f-tags">
      <span class="tag tag-conf conf-{conf.lower()}">Confidence: {_esc(conf)}</span>
      <span class="tag">CVSS {cvss}</span>
      <span class="tag">{_esc(cwe)}</span>
      <span class="tag">{_esc(owasp_str)}</span>
      <span class="tag tag-method">{_esc(f.method)}</span>
    </div>

    <dl class="f-meta">
      {meta("Location", f'<code>{_esc(f.url)}</code>', mono=True)}
      {meta("Parameter", f'<code>{_esc(f.parameter)}</code>' if f.parameter else "<span class='muted'>—</span>", mono=True)}
      {meta("Detected", _fmt_ts(f.timestamp))}
      {meta("Fingerprint", f'<code>{_esc(f.fingerprint)}</code>', mono=True)}
    </dl>

    <div class="f-block">
      <div class="blk-head"><h4 class="blk-label blk-poc">Proof of Concept</h4>
        <button class="copy-btn" type="button" data-copy="pre">Copy</button></div>
      <pre class="code poc">{_esc(f.payload) or "<span class='muted'>—</span>"}</pre>
    </div>

    <div class="f-block">
      <div class="blk-head"><h4 class="blk-label blk-evi">Evidence</h4>
        <button class="copy-btn" type="button" data-copy="pre">Copy</button></div>
      <pre class="code evidence">{evidence}</pre>
    </div>

    <div class="f-block">
      <h4 class="blk-label blk-fix">Remediation</h4>
      <div class="remediation">{_esc(f.remediation)}</div>
    </div>
  </div>
</article>"""


# ---------------------------------------------------------------------------
# Appendix A — Scope & Methodology
# ---------------------------------------------------------------------------

def _methodology(summary: ScanSummary) -> str:
    key_rows = "".join(
        f'<tr class="lg-{_SEV_CLASS[s]}"><td class="lg-name"><span class="lg-dot"></span>{s}</td>'
        f'<td class="lg-cvss">{Severity.CVSS_RANGES.get(s, "—")}</td>'
        f'<td class="key-desc">{_SEV_DESC[s]}</td></tr>'
        for s in _SEV_ORDER
    )
    return f"""
<section id="scope" class="sec">
  <div class="sec-head"><span class="sec-num">A</span><h2>Scope &amp; Methodology</h2></div>
  <div class="method-grid">
    <div class="method-card">
      <h4 class="mc-label">Scope</h4>
      <p>The assessment targeted <code>{_esc(summary.target_url)}</code> and hosts reachable
      from it within the crawl boundary. Assessment type: {_esc(summary.scan_type)}.</p>
    </div>
    <div class="method-card">
      <h4 class="mc-label">Approach</h4>
      <p>Automated reconnaissance and crawling to enumerate pages, forms and parameters,
      followed by active injection and configuration testing. Each candidate issue is
      confirmed against response evidence before being reported.</p>
    </div>
    <div class="method-card">
      <h4 class="mc-label">Coverage</h4>
      <p>{summary.pages_crawled} page(s) crawled · {summary.forms_found} form(s) discovered ·
      {summary.params_tested} parameter(s) exercised.</p>
    </div>
    <div class="method-card">
      <h4 class="mc-label">Limitations</h4>
      <p>Automated testing cannot fully assess business-logic flaws, authorisation
      boundaries or chained exploits. Absence of findings is not proof of security; a
      manual review is recommended for high-assurance systems.</p>
    </div>
  </div>

  <h3 class="key-head">Severity Rating Key</h3>
  <table class="legend key-table">
    <thead><tr><th>Severity</th><th>CVSS v3.1</th><th>Definition</th></tr></thead>
    <tbody>{key_rows}</tbody>
  </table>
</section>"""


# ---------------------------------------------------------------------------
# Footer
# ---------------------------------------------------------------------------

def _footer(summary: ScanSummary) -> str:
    now = datetime.utcnow()
    year = now.year
    generated = now.strftime("%Y-%m-%d %H:%M UTC")
    ref = _report_ref(summary)
    return f"""
<footer class="doc-footer">
  <div class="foot-top">
    <div class="foot-id">
      <div class="foot-brand">W<i>3</i>BSP<i>1</i>D<i>3</i>R</div>
      <p class="foot-tag">Automated Web Application Vulnerability Assessment</p>
    </div>
    <dl class="foot-meta">
      <div><dt>Report Ref.</dt><dd>{_esc(ref)}</dd></div>
      <div><dt>Generated</dt><dd>{_esc(generated)}</dd></div>
      <div><dt>Classification</dt><dd class="foot-class">Confidential</dd></div>
    </dl>
  </div>
  <div class="foot-legal">
    <p><strong>Authorised testing only.</strong> Assessing systems without explicit written
    permission may constitute an offence under the Computer Fraud and Abuse Act
    (18 U.S.C. &sect; 1030) and equivalent legislation in other jurisdictions. This document is
    confidential and intended solely for the system owner; unauthorised distribution or
    disclosure may be unlawful. Findings reflect the state of the target at the time of scanning.</p>
    <p class="foot-copy">&copy; {year} W3BSP1D3R v1.0.0 &middot; Engine and report by S1YOL &middot; All rights reserved.</p>
  </div>
</footer>"""


# ---------------------------------------------------------------------------
# Decorative spider-web line art (subtle, cover only)
# ---------------------------------------------------------------------------
_WEB_SVG = """<svg class="web-art" viewBox="0 0 260 260" aria-hidden="true" focusable="false">
  <g fill="none" stroke="currentColor" stroke-width="0.9" stroke-linecap="round">
    <line x1="260" y1="0" x2="0" y2="0"/>
    <line x1="260" y1="0" x2="12.7" y2="80.3"/>
    <line x1="260" y1="0" x2="49.6" y2="152.8"/>
    <line x1="260" y1="0" x2="107.2" y2="210.4"/>
    <line x1="260" y1="0" x2="179.7" y2="247.3"/>
    <line x1="260" y1="0" x2="260" y2="260"/>
    <path d="M216 0 A44 44 0 0 0 260 44"/>
    <path d="M168 0 A92 92 0 0 0 260 92"/>
    <path d="M120 0 A140 140 0 0 0 260 140"/>
    <path d="M72 0 A188 188 0 0 0 260 188"/>
    <path d="M24 0 A236 236 0 0 0 260 236"/>
  </g>
</svg>"""


# ---------------------------------------------------------------------------
# Embedded CSS
# ---------------------------------------------------------------------------
_CSS = """<style>
:root{
  --paper:#eef0f3; --surface:#ffffff; --surface-2:#f5f7f9;
  --ink:#14181d; --ink-2:#48515c; --ink-3:#79828d;
  --line:#e0e4e9; --line-strong:#ccd2da;
  --brand:#b3283f; --brand-2:#8f1e32;
  --sev-critical:#c81e3a; --sev-high:#df5f1b; --sev-medium:#bd8a00;
  --sev-low:#3a72a8; --sev-none:#2f9e6f;
  --ring-empty:#d5dae0;
  --shadow:none;
  --elev:0 8px 22px rgba(12,16,22,.14);
  --radius:8px;
  --serif:'Iowan Old Style','Palatino Linotype','Book Antiqua',Palatino,Georgia,'Times New Roman',serif;
  --sans:system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;
  --mono:'SFMono-Regular',ui-monospace,'JetBrains Mono','Cascadia Code',Consolas,'Liberation Mono',monospace;
}
@media (prefers-color-scheme: dark){
  :root{
    --paper:#0c0f13; --surface:#14181e; --surface-2:#1a1f26;
    --ink:#e7eaee; --ink-2:#9aa4b0; --ink-3:#6b7480;
    --line:#242b33; --line-strong:#333b45;
    --brand:#e0546b; --brand-2:#c23d54;
    --sev-critical:#f0637a; --sev-high:#ef8b45; --sev-medium:#dcb14a;
    --sev-low:#6fa8d8; --sev-none:#57c493;
    --ring-empty:#2a323b;
    --shadow:none;
  }
}
:root[data-theme="light"]{
  --paper:#eef0f3; --surface:#ffffff; --surface-2:#f5f7f9;
  --ink:#14181d; --ink-2:#48515c; --ink-3:#79828d;
  --line:#e0e4e9; --line-strong:#ccd2da;
  --brand:#b3283f; --brand-2:#8f1e32;
  --sev-critical:#c81e3a; --sev-high:#df5f1b; --sev-medium:#bd8a00;
  --sev-low:#3a72a8; --sev-none:#2f9e6f; --ring-empty:#d5dae0;
  --shadow:none;
}
:root[data-theme="dark"]{
  --paper:#0c0f13; --surface:#14181e; --surface-2:#1a1f26;
  --ink:#e7eaee; --ink-2:#9aa4b0; --ink-3:#6b7480;
  --line:#242b33; --line-strong:#333b45;
  --brand:#e0546b; --brand-2:#c23d54;
  --sev-critical:#f0637a; --sev-high:#ef8b45; --sev-medium:#dcb14a;
  --sev-low:#6fa8d8; --sev-none:#57c493; --ring-empty:#2a323b;
  --shadow:none;
}

*{box-sizing:border-box;}
html{scroll-behavior:smooth;}
body{margin:0;background:var(--paper);color:var(--ink);font-family:var(--sans);
  line-height:1.6;-webkit-font-smoothing:antialiased;font-size:15px;}
code,pre,.mono{font-family:var(--mono);}
.muted{color:var(--ink-3);}
:where(a){color:var(--brand);text-decoration:none;}
:focus-visible{outline:2px solid var(--brand);outline-offset:2px;border-radius:4px;}
.sec,.finding,:target{scroll-margin-top:74px;}

/* ---------- Toolbar ---------- */
.toolbar{position:sticky;top:0;z-index:50;background:color-mix(in srgb,var(--surface) 88%,transparent);
  -webkit-backdrop-filter:blur(10px);backdrop-filter:blur(10px);border-bottom:1px solid var(--line);}
.tb-inner{max-width:900px;margin:0 auto;padding:.55rem 2.2rem;display:flex;align-items:center;gap:.9rem;}
.tb-brand{font-family:var(--mono);font-weight:700;letter-spacing:.12em;font-size:.9rem;}
.tb-brand i{font-style:normal;color:var(--brand);}
.tb-ref{font-family:var(--mono);font-size:.72rem;color:var(--ink-3);letter-spacing:.05em;}
.tb-actions{margin-left:auto;display:flex;gap:.5rem;}
.tb-btn{display:inline-flex;align-items:center;gap:.4rem;font-family:var(--sans);font-size:.78rem;
  font-weight:600;color:var(--ink-2);background:var(--surface-2);border:1px solid var(--line);
  padding:.4rem .7rem;border-radius:7px;cursor:pointer;transition:.15s;}
.tb-btn:hover{color:var(--brand);border-color:var(--brand);}
.tb-ico{font-size:.9rem;line-height:1;}

/* ---------- Cover ---------- */
.cover{position:relative;overflow:hidden;color:#e9ecf2;
  background:radial-gradient(120% 140% at 85% -10%, #1b2230 0%, #0d1218 55%, #090c11 100%);
  border-bottom:3px solid var(--brand);}
.web-art{position:absolute;top:-30px;right:-30px;width:min(48vw,440px);height:auto;
  color:#ffffff;opacity:.09;pointer-events:none;}
.cover-inner{position:relative;max-width:900px;margin:0 auto;padding:2.4rem 2.2rem 2rem;z-index:1;}
.cover-top{display:flex;justify-content:space-between;align-items:flex-start;gap:1rem;
  padding-bottom:1.6rem;margin-bottom:1.8rem;border-bottom:1px solid rgba(255,255,255,.1);}
.brand-mark{display:block;font-family:var(--mono);font-weight:700;font-size:1.5rem;letter-spacing:.18em;color:#fff;}
.brand-mark i{font-style:normal;color:var(--brand);}
.brand-sub{display:block;font-size:.66rem;letter-spacing:.34em;text-transform:uppercase;color:#8a94a3;margin-top:.35rem;}
.cover-ref{text-align:right;}
.ref-label{display:block;font-size:.6rem;letter-spacing:.22em;text-transform:uppercase;color:#8a94a3;}
.ref-val{display:block;font-family:var(--mono);font-size:.92rem;color:#cfd6e0;margin-top:.25rem;letter-spacing:.06em;}
.eyebrow{margin:0 0 .5rem;font-size:.72rem;letter-spacing:.32em;text-transform:uppercase;color:var(--brand);font-weight:600;}
.cover-title h1{margin:0;font-family:var(--serif);font-weight:600;font-size:clamp(2rem,5vw,3rem);
  letter-spacing:-.01em;line-height:1.08;color:#fff;text-wrap:balance;}
.cover-target{display:flex;align-items:baseline;gap:.7rem;margin:1.1rem 0 0;flex-wrap:wrap;}
.cover-target span{font-size:.64rem;letter-spacing:.2em;text-transform:uppercase;color:#8a94a3;}
.cover-target code{font-size:1rem;color:#e9ecf2;background:rgba(255,255,255,.06);
  border:1px solid rgba(255,255,255,.12);padding:.28rem .6rem;border-radius:6px;word-break:break-all;}
.verdict{display:flex;align-items:center;gap:1.3rem;margin:2rem 0 1.8rem;padding:1.15rem 1.3rem;
  border-radius:var(--radius);background:rgba(255,255,255,.04);border:1px solid rgba(255,255,255,.09);
  border-left:5px solid var(--vc,#8a94a3);}
.verdict-critical{--vc:var(--sev-critical);} .verdict-high{--vc:var(--sev-high);}
.verdict-medium{--vc:var(--sev-medium);} .verdict-low{--vc:var(--sev-low);} .verdict-none{--vc:var(--sev-none);}
.verdict-badge{display:flex;flex-direction:column;min-width:150px;}
.verdict-kicker{font-size:.62rem;letter-spacing:.2em;text-transform:uppercase;color:#8a94a3;}
.verdict-label{font-family:var(--serif);font-size:1.5rem;font-weight:600;color:var(--vc);line-height:1.15;margin-top:.1rem;}
.verdict-text{margin:0;font-size:.86rem;color:#b9c1cc;line-height:1.55;}
.cover-meta{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:0;margin:0;
  border:1px solid rgba(255,255,255,.1);border-radius:var(--radius);overflow:hidden;}
.cover-meta>div{padding:.75rem .95rem;border-right:1px solid rgba(255,255,255,.08);}
.cover-meta>div:last-child{border-right:none;}
.cover-meta dt{font-size:.6rem;letter-spacing:.18em;text-transform:uppercase;color:#8a94a3;}
.cover-meta dd{margin:.3rem 0 0;font-size:.9rem;color:#dfe4ea;}
.confidential{margin:0;padding:.7rem 2.2rem;text-align:center;font-size:.68rem;letter-spacing:.16em;
  text-transform:uppercase;color:#8089a0;background:rgba(0,0,0,.35);border-top:1px solid rgba(255,255,255,.06);}

/* ---------- Document shell ---------- */
.doc{max-width:900px;margin:0 auto;padding:2.4rem 2.2rem 1rem;}
.sec{margin:0 0 3rem;}
.sec-head{display:flex;align-items:center;gap:.85rem;margin:0 0 1.1rem;padding-bottom:.7rem;border-bottom:2px solid var(--line-strong);}
.sec-num{font-family:var(--serif);font-size:1.05rem;font-weight:600;color:var(--brand);letter-spacing:.02em;}
.sec-head h2{margin:0;font-family:var(--serif);font-weight:600;font-size:1.5rem;letter-spacing:-.01em;flex:1;}
.sec-count{font-family:var(--mono);font-size:.78rem;font-weight:700;color:var(--ink-2);
  background:var(--surface-2);border:1px solid var(--line);padding:.1rem .5rem;border-radius:6px;}
.sec-intro{color:var(--ink-2);margin:.2rem 0 1.2rem;font-size:.92rem;}
.table-wrap{overflow-x:auto;}

/* ---------- Contents ---------- */
.toc{background:var(--surface);border:1px solid var(--line);border-radius:var(--radius);box-shadow:var(--shadow);
  padding:1.1rem 1.3rem;margin:0 0 2.6rem;}
.toc-head{margin:0 0 .5rem;font-size:.66rem;letter-spacing:.26em;text-transform:uppercase;color:var(--ink-3);}
.toc-row{display:flex;align-items:baseline;gap:.75rem;padding:.5rem 0;border-top:1px solid var(--line);color:var(--ink);transition:color .15s;}
.toc-row:first-of-type{border-top:none;}
.toc-row:hover{color:var(--brand);}
.toc-num{font-family:var(--mono);font-size:.8rem;color:var(--brand);font-weight:700;width:1.8rem;}
.toc-name{font-weight:500;}
.toc-dots{flex:1;border-bottom:1px dotted var(--line-strong);transform:translateY(-.2rem);}

/* ---------- Executive summary ---------- */
.lead{font-family:var(--serif);font-size:1.28rem;line-height:1.55;color:var(--ink);
  margin:.4rem 0 1.8rem;padding:.1rem 0 .1rem 1.4rem;border-left:2px solid var(--lc,var(--brand));
  max-width:62ch;font-weight:400;}
.lead strong{font-weight:600;}
.lead code{background:var(--surface-2);border:1px solid var(--line);padding:.05rem .35rem;border-radius:4px;font-size:.85em;word-break:break-all;}
.lead-critical{--lc:var(--sev-critical);} .lead-high{--lc:var(--sev-high);}
.lead-medium{--lc:var(--sev-medium);} .lead-low{--lc:var(--sev-low);} .lead-none{--lc:var(--sev-none);}
.stat-row{display:grid;grid-template-columns:repeat(4,1fr);gap:1px;margin:0 0 1.4rem;
  background:var(--line);border:1px solid var(--line);border-radius:var(--radius);overflow:hidden;}
.stat{background:var(--surface);padding:1.15rem 1rem;text-align:center;}
.stat-num{font-family:var(--serif);font-size:2.1rem;font-weight:600;line-height:1;font-variant-numeric:tabular-nums;}
.stat-label{font-size:.66rem;letter-spacing:.12em;text-transform:uppercase;color:var(--ink-3);margin-top:.5rem;}
.sev-tiles{display:grid;grid-template-columns:repeat(4,1fr);gap:1px;
  background:var(--line);border:1px solid var(--line);border-radius:var(--radius);overflow:hidden;}
.sev-tile{display:flex;flex-direction:column;gap:.35rem;padding:1rem;background:var(--surface);}
.sev-tile .sev-dot{width:.75rem;height:.75rem;border-radius:2px;background:var(--tc);}
.sev-count{font-family:var(--serif);font-size:1.75rem;font-weight:600;line-height:1;color:var(--tc);font-variant-numeric:tabular-nums;}
.sev-name{font-size:.7rem;letter-spacing:.12em;text-transform:uppercase;color:var(--ink-3);}
.sev-critical{--tc:var(--sev-critical);} .sev-high{--tc:var(--sev-high);}
.sev-medium{--tc:var(--sev-medium);} .sev-low{--tc:var(--sev-low);}

/* ---------- Risk profile ---------- */
.risk-grid{display:grid;grid-template-columns:200px 1fr;gap:2rem;align-items:center;
  background:var(--surface);border:1px solid var(--line);border-radius:var(--radius);padding:1.6rem;box-shadow:var(--shadow);}
.donut{margin:0;justify-self:center;width:180px;height:180px;border-radius:50%;
  background:conic-gradient(var(--donut));display:grid;place-items:center;box-shadow:inset 0 0 0 1px rgba(0,0,0,.04);}
.donut-hole{width:118px;height:118px;border-radius:50%;background:var(--surface);display:grid;place-items:center;
  text-align:center;box-shadow:0 0 0 1px var(--line);}
.donut-total{font-family:var(--serif);font-size:2.4rem;font-weight:600;line-height:1;font-variant-numeric:tabular-nums;}
.donut-sub{font-size:.66rem;letter-spacing:.14em;text-transform:uppercase;color:var(--ink-3);}
.legend{width:100%;border-collapse:collapse;font-size:.86rem;}
.legend th{text-align:left;font-size:.62rem;letter-spacing:.14em;text-transform:uppercase;color:var(--ink-3);
  font-weight:600;padding:0 .6rem .6rem;border-bottom:1px solid var(--line);}
.legend td{padding:.55rem .6rem;border-bottom:1px solid var(--line);vertical-align:middle;}
.legend tr:last-child td{border-bottom:none;}
.lg-name{font-weight:600;white-space:nowrap;}
.lg-dot{display:inline-block;width:.6rem;height:.6rem;border-radius:2px;margin-right:.5rem;vertical-align:middle;}
.lg-cvss{font-family:var(--mono);color:var(--ink-2);font-size:.8rem;white-space:nowrap;}
.lg-track{display:block;height:8px;background:var(--surface-2);border-radius:99px;overflow:hidden;min-width:80px;}
.lg-fill{display:block;height:100%;border-radius:99px;}
.lg-count{text-align:right;font-family:var(--mono);font-weight:700;font-variant-numeric:tabular-nums;}
.lg-critical .lg-dot,.lg-critical .lg-fill{background:var(--sev-critical);}
.lg-high .lg-dot,.lg-high .lg-fill{background:var(--sev-high);}
.lg-medium .lg-dot,.lg-medium .lg-fill{background:var(--sev-medium);}
.lg-low .lg-dot,.lg-low .lg-fill{background:var(--sev-low);}

/* ---------- Tables (OWASP + roadmap) ---------- */
.owasp-table,.roadmap-table{width:100%;border-collapse:collapse;font-size:.9rem;background:var(--surface);
  border:1px solid var(--line);border-radius:var(--radius);overflow:hidden;box-shadow:var(--shadow);}
.owasp-table th,.roadmap-table th{text-align:left;font-size:.62rem;letter-spacing:.14em;text-transform:uppercase;
  color:var(--ink-3);font-weight:600;padding:.8rem 1rem;background:var(--surface-2);border-bottom:1px solid var(--line);}
.owasp-table td,.roadmap-table td{padding:.75rem 1rem;border-bottom:1px solid var(--line);vertical-align:top;}
.owasp-table tr:last-child td,.roadmap-table tr:last-child td{border-bottom:none;}
.ow-id{font-family:var(--mono);font-weight:700;color:var(--brand);white-space:nowrap;}
.ow-n,.rm-inst{text-align:left;}
.ow-n{text-align:right;font-family:var(--mono);font-weight:700;font-variant-numeric:tabular-nums;}
.mini-chip{display:inline-block;font-size:.66rem;font-weight:600;padding:.12rem .45rem;border-radius:5px;
  margin:.1rem .25rem .1rem 0;letter-spacing:.02em;border:1px solid transparent;}
.mini-chip.sev-critical{color:var(--sev-critical);background:color-mix(in srgb,var(--sev-critical) 12%,var(--surface));border-color:color-mix(in srgb,var(--sev-critical) 28%,transparent);}
.mini-chip.sev-high{color:var(--sev-high);background:color-mix(in srgb,var(--sev-high) 13%,var(--surface));border-color:color-mix(in srgb,var(--sev-high) 28%,transparent);}
.mini-chip.sev-medium{color:color-mix(in srgb,var(--sev-medium) 78%,var(--ink));background:color-mix(in srgb,var(--sev-medium) 16%,var(--surface));border-color:color-mix(in srgb,var(--sev-medium) 34%,transparent);}
.mini-chip.sev-low{color:var(--sev-low);background:color-mix(in srgb,var(--sev-low) 13%,var(--surface));border-color:color-mix(in srgb,var(--sev-low) 28%,transparent);}
.rm-pri{white-space:nowrap;}
.pri-badge{display:inline-block;font-family:var(--mono);font-weight:700;font-size:.76rem;
  padding:.18rem .45rem;border-radius:5px;border:1px solid transparent;}
.pri-badge.sev-critical{color:var(--sev-critical);background:color-mix(in srgb,var(--sev-critical) 13%,var(--surface));border-color:color-mix(in srgb,var(--sev-critical) 30%,transparent);}
.pri-badge.sev-high{color:var(--sev-high);background:color-mix(in srgb,var(--sev-high) 14%,var(--surface));border-color:color-mix(in srgb,var(--sev-high) 30%,transparent);}
.pri-badge.sev-medium{color:color-mix(in srgb,var(--sev-medium) 78%,var(--ink));background:color-mix(in srgb,var(--sev-medium) 17%,var(--surface));border-color:color-mix(in srgb,var(--sev-medium) 36%,transparent);}
.pri-badge.sev-low{color:var(--sev-low);background:color-mix(in srgb,var(--sev-low) 14%,var(--surface));border-color:color-mix(in srgb,var(--sev-low) 30%,transparent);}
.rm-type{display:block;font-weight:600;}
.rm-cwe{display:block;font-family:var(--mono);font-size:.72rem;color:var(--ink-3);margin-top:.15rem;}
.rm-inst{white-space:nowrap;color:var(--ink-2);font-size:.84rem;}
.rm-action{color:var(--ink-2);font-size:.85rem;line-height:1.55;min-width:220px;}

/* ---------- Filter bar ---------- */
.filter-bar{display:flex;flex-wrap:wrap;gap:.7rem;align-items:center;margin:0 0 1.2rem;padding:.8rem;
  background:var(--surface);border:1px solid var(--line);border-radius:var(--radius);box-shadow:var(--shadow);}
.filter-search{position:relative;flex:1 1 240px;min-width:200px;}
.fs-ico{position:absolute;left:.65rem;top:50%;transform:translateY(-50%) rotate(45deg);color:var(--ink-3);font-size:.9rem;}
.find-search{width:100%;font-family:var(--sans);font-size:.85rem;color:var(--ink);background:var(--surface-2);
  border:1px solid var(--line);border-radius:7px;padding:.5rem .7rem .5rem 2rem;}
.find-search:focus{outline:none;border-color:var(--brand);}
.filter-chips{display:flex;flex-wrap:wrap;gap:.4rem;}
.filter-chip{display:inline-flex;align-items:center;gap:.4rem;font-family:var(--sans);font-size:.76rem;font-weight:600;
  color:var(--ink);background:var(--surface-2);border:1px solid var(--line);padding:.38rem .6rem;border-radius:6px;cursor:pointer;transition:.15s;}
.filter-chip .chip-dot{width:.55rem;height:.55rem;border-radius:50%;background:var(--cc);}
.filter-chip .chip-n{font-family:var(--mono);font-size:.7rem;color:var(--ink-3);}
.filter-chip.sev-critical{--cc:var(--sev-critical);} .filter-chip.sev-high{--cc:var(--sev-high);}
.filter-chip.sev-medium{--cc:var(--sev-medium);} .filter-chip.sev-low{--cc:var(--sev-low);}
.filter-chip:hover{border-color:var(--cc);}
.filter-chip.off{opacity:.4;text-decoration:line-through;}
.filter-tools{display:flex;align-items:center;gap:.55rem;margin-left:auto;}
.filter-count{font-size:.75rem;color:var(--ink-3);white-space:nowrap;}
.filter-count #filterCount{font-family:var(--mono);color:var(--ink-2);}
.mini-btn{font-family:var(--sans);font-size:.74rem;font-weight:600;color:var(--ink-2);background:transparent;
  border:1px solid var(--line);padding:.35rem .55rem;border-radius:6px;cursor:pointer;transition:.15s;}
.mini-btn:hover{color:var(--brand);border-color:var(--brand);}
.no-match{padding:1.2rem;text-align:center;color:var(--ink-3);background:var(--surface);border:1px dashed var(--line-strong);border-radius:var(--radius);}
.findings-list{display:flex;flex-direction:column;gap:1.3rem;}

/* ---------- Findings ---------- */
.finding{background:var(--surface);border:1px solid var(--line);border-radius:var(--radius);
  padding:0;overflow:hidden;}
.sev-border-critical{--fc:var(--sev-critical);} .sev-border-high{--fc:var(--sev-high);}
.sev-border-medium{--fc:var(--sev-medium);} .sev-border-low{--fc:var(--sev-low);}
.f-head{display:flex;align-items:stretch;gap:0;background:color-mix(in srgb,var(--fc) 4%,var(--surface));
  border-bottom:1px solid var(--line);}
.finding.collapsed .f-head{border-bottom:none;}
.f-head-btn{flex:1;display:flex;align-items:center;gap:1rem;background:transparent;border:none;cursor:pointer;
  text-align:left;font-family:inherit;color:var(--ink);padding:.95rem 1.2rem;width:100%;min-width:0;}
.f-head-btn .f-ref,.f-head-btn .pill,.f-head-btn .caret{flex:none;}
.f-ref{font-family:var(--mono);font-size:.76rem;font-weight:700;color:#fff;background:var(--fc);
  border:none;padding:.24rem .5rem;border-radius:5px;letter-spacing:.02em;}
.sev-border-medium .f-ref{color:#241a00;}
.f-title{flex:1;font-family:var(--serif);font-size:1.3rem;font-weight:600;letter-spacing:-.01em;line-height:1.25;}
.pill{font-size:.64rem;font-weight:700;letter-spacing:.07em;text-transform:uppercase;padding:.26rem .55rem;
  border-radius:6px;white-space:nowrap;border:1px solid transparent;}
.pill.sev-critical{color:var(--sev-critical);background:color-mix(in srgb,var(--sev-critical) 13%,var(--surface));border-color:color-mix(in srgb,var(--sev-critical) 32%,transparent);}
.pill.sev-high{color:var(--sev-high);background:color-mix(in srgb,var(--sev-high) 14%,var(--surface));border-color:color-mix(in srgb,var(--sev-high) 32%,transparent);}
.pill.sev-medium{color:color-mix(in srgb,var(--sev-medium) 78%,var(--ink));background:color-mix(in srgb,var(--sev-medium) 17%,var(--surface));border-color:color-mix(in srgb,var(--sev-medium) 38%,transparent);}
.pill.sev-low{color:var(--sev-low);background:color-mix(in srgb,var(--sev-low) 14%,var(--surface));border-color:color-mix(in srgb,var(--sev-low) 32%,transparent);}
.caret{width:.6rem;height:.6rem;border-right:2px solid var(--ink-3);border-bottom:2px solid var(--ink-3);
  transform:rotate(45deg);transition:transform .2s;flex:none;}
.finding.collapsed .caret{transform:rotate(-45deg);}
.icon-btn{flex:none;width:2.6rem;background:transparent;border:none;border-left:1px solid var(--line);color:var(--ink-3);
  font-family:var(--mono);font-size:1rem;cursor:pointer;transition:.15s;}
.icon-btn:hover{color:var(--brand);background:var(--surface-2);}
.icon-btn.copied{color:var(--sev-none);}
.f-body{padding:1.25rem 1.3rem 1.35rem;}
.finding.collapsed .f-body{display:none;}
.f-tags{display:flex;flex-wrap:wrap;gap:.55rem;margin-bottom:1.2rem;}
.tag{font-size:.7rem;font-weight:600;color:var(--ink-2);background:var(--surface-2);border:1px solid var(--line);
  padding:.3rem .62rem;border-radius:6px;letter-spacing:.01em;line-height:1;}
.tag-method{font-family:var(--mono);}
.tag-conf{border-color:transparent;}
.conf-certain{background:color-mix(in srgb,var(--sev-none) 16%,transparent);color:var(--sev-none);}
.conf-firm{background:color-mix(in srgb,var(--sev-low) 16%,transparent);color:var(--sev-low);}
.conf-tentative{background:color-mix(in srgb,var(--sev-medium) 18%,transparent);color:var(--sev-medium);}
.f-meta{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:.1rem 1.5rem;margin:0 0 1.2rem;
  border-top:1px solid var(--line);border-bottom:1px solid var(--line);padding:.4rem 0;}
.mrow{display:grid;grid-template-columns:98px 1fr;gap:.5rem;align-items:baseline;padding:.4rem 0;}
.mrow dt{font-size:.64rem;letter-spacing:.1em;text-transform:uppercase;color:var(--ink-3);font-weight:600;}
.mrow dd{margin:0;font-size:.86rem;min-width:0;}
.mrow dd code{word-break:break-all;color:var(--ink);}
.f-block{margin-top:1.1rem;}
.blk-head{display:flex;align-items:center;justify-content:space-between;margin-bottom:.45rem;}
.blk-label{margin:0;font-size:.64rem;letter-spacing:.16em;text-transform:uppercase;font-weight:700;color:var(--ink-2);
  display:flex;align-items:center;gap:.45rem;}
.blk-label::before{content:"";width:.7rem;height:2px;border-radius:2px;background:var(--ink-3);}
.blk-poc::before{background:var(--sev-critical);}
.blk-evi::before{background:var(--ink-3);}
.blk-fix::before{background:var(--sev-none);}
.copy-btn{font-family:var(--sans);font-size:.68rem;font-weight:600;color:var(--ink-3);background:transparent;
  border:1px solid var(--line);padding:.2rem .5rem;border-radius:6px;cursor:pointer;transition:.15s;}
.copy-btn:hover{color:var(--brand);border-color:var(--brand);}
.copy-btn.copied{color:var(--sev-none);border-color:var(--sev-none);}
.code{margin:0;font-size:.82rem;line-height:1.55;padding:.85rem 1rem;border-radius:8px;overflow-x:auto;
  white-space:pre-wrap;word-break:break-word;}
.poc{background:color-mix(in srgb,var(--sev-critical) 7%,var(--surface));
  border:1px solid color-mix(in srgb,var(--sev-critical) 22%,var(--line));color:var(--ink);}
.evidence{background:var(--surface-2);border:1px solid var(--line);color:var(--ink-2);}
.remediation{background:color-mix(in srgb,var(--sev-none) 7%,var(--surface));
  border:1px solid color-mix(in srgb,var(--sev-none) 24%,var(--line));border-radius:8px;padding:.85rem 1rem;
  font-size:.9rem;color:var(--ink);line-height:1.6;}

/* ---------- Clean state ---------- */
.clean-state{display:flex;gap:1rem;align-items:flex-start;background:color-mix(in srgb,var(--sev-none) 8%,var(--surface));
  border:1px solid color-mix(in srgb,var(--sev-none) 26%,var(--line));border-radius:var(--radius);padding:1.3rem 1.4rem;}
.clean-check{flex:none;width:2.2rem;height:2.2rem;border-radius:50%;background:var(--sev-none);color:#fff;
  display:grid;place-items:center;font-size:1.2rem;font-weight:700;}
.clean-state strong{font-size:1.05rem;}
.clean-state p{margin:.35rem 0 0;color:var(--ink-2);font-size:.9rem;}

/* ---------- Methodology ---------- */
.method-grid{display:grid;grid-template-columns:repeat(2,1fr);gap:1rem;margin-bottom:2rem;}
.method-card{background:var(--surface);border:1px solid var(--line);border-radius:var(--radius);padding:1.1rem 1.2rem;box-shadow:var(--shadow);}
.mc-label{margin:0 0 .5rem;font-size:.64rem;letter-spacing:.16em;text-transform:uppercase;font-weight:700;color:var(--brand);}
.method-card p{margin:0;font-size:.88rem;color:var(--ink-2);line-height:1.6;}
.method-card code{background:var(--surface-2);border:1px solid var(--line);padding:.05rem .35rem;border-radius:4px;font-size:.85em;word-break:break-all;color:var(--ink);}
.key-head{margin:0 0 .8rem;font-size:.72rem;letter-spacing:.16em;text-transform:uppercase;color:var(--ink-3);}
.key-table{background:var(--surface);border:1px solid var(--line);border-radius:var(--radius);box-shadow:var(--shadow);}
.key-table th{padding:.8rem 1rem;}
.key-table td{padding:.7rem 1rem;}
.key-desc{color:var(--ink-2);font-size:.84rem;line-height:1.55;}

/* ---------- Footer + back to top ---------- */
.doc-footer{max-width:900px;margin:2.4rem auto 0;padding:1.8rem 2.2rem 2.6rem;border-top:2px solid var(--brand);}
.foot-top{display:flex;flex-wrap:wrap;justify-content:space-between;align-items:flex-start;gap:1.4rem;
  padding-bottom:1.3rem;margin-bottom:1.3rem;border-bottom:1px solid var(--line);}
.foot-brand{font-family:var(--mono);font-weight:700;letter-spacing:.16em;font-size:1.05rem;color:var(--ink);}
.foot-brand i{font-style:normal;color:var(--brand);}
.foot-tag{margin:.4rem 0 0;font-size:.64rem;letter-spacing:.22em;text-transform:uppercase;color:var(--ink-3);}
.foot-meta{display:flex;flex-wrap:wrap;gap:0;margin:0;text-align:right;}
.foot-meta>div{padding:0 0 0 1.4rem;margin-left:1.4rem;border-left:1px solid var(--line);}
.foot-meta>div:first-child{border-left:none;margin-left:0;padding-left:0;}
.foot-meta dt{font-size:.58rem;letter-spacing:.18em;text-transform:uppercase;color:var(--ink-3);font-weight:600;}
.foot-meta dd{margin:.35rem 0 0;font-family:var(--mono);font-size:.82rem;color:var(--ink-2);}
.foot-class{color:var(--brand)!important;font-weight:700;letter-spacing:.03em;}
.foot-legal{margin:0;}
.foot-legal p{margin:0;font-size:.72rem;line-height:1.65;color:var(--ink-3);max-width:78ch;}
.foot-legal strong{color:var(--ink-2);}
.foot-copy{margin-top:.7rem!important;font-family:var(--mono);font-size:.68rem;letter-spacing:.02em;color:var(--ink-3);}
.to-top{position:fixed;right:1.4rem;bottom:1.4rem;z-index:40;width:2.6rem;height:2.6rem;border-radius:50%;
  background:var(--brand);color:#fff;border:none;font-size:1.1rem;cursor:pointer;box-shadow:0 6px 20px rgba(0,0,0,.25);
  opacity:0;visibility:hidden;transform:translateY(8px);transition:.2s;}
.to-top.show{opacity:1;visibility:visible;transform:none;}
.to-top:hover{background:var(--brand-2);}

/* ---------- Responsive ---------- */
@media (max-width:720px){
  .stat-row,.sev-tiles,.method-grid{grid-template-columns:repeat(2,1fr);}
  .risk-grid,.f-meta{grid-template-columns:1fr;}
  .cover-inner,.doc,.tb-inner{padding-left:1.2rem;padding-right:1.2rem;}
  .verdict{flex-direction:column;align-items:flex-start;gap:.6rem;}
  .tb-txt{display:none;}
  .filter-tools{margin-left:0;width:100%;}
}
@media (prefers-reduced-motion:reduce){*{transition:none!important;scroll-behavior:auto;}}

/* ---------- Print ---------- */
@media print{
  :root{--paper:#fff;--surface:#fff;--surface-2:#f4f5f7;--ink:#111;--ink-2:#444;--ink-3:#666;
    --line:#dcdfe4;--line-strong:#bcc2ca;--shadow:none;}
  body{background:#fff;}
  .toolbar,.to-top,.filter-bar,.icon-btn,.copy-btn,.caret,.web-art{display:none!important;}
  .finding.collapsed .f-body{display:block!important;}
  .cover{color:#111;background:#fff;border-bottom:3px solid var(--brand);}
  .cover-top{border-color:var(--line);}
  .brand-mark,.cover-title h1,.cover-target code{color:#111;}
  .brand-sub,.ref-label,.cover-target span,.cover-meta dt{color:#555;}
  .verdict{background:#f7f8fa;border-color:var(--line);}
  .verdict-text,.cover-meta dd{color:#333;}
  .confidential{background:#f0f1f3;color:#555;}
  .cover-meta,.cover-meta>div{border-color:var(--line);}
  .sec,.finding,.risk-grid,.owasp-table,.roadmap-table,.toc,.method-card{break-inside:avoid;page-break-inside:avoid;}
  a{color:#111;}
}
</style>"""


# ---------------------------------------------------------------------------
# Embedded JavaScript — progressive enhancement (report works without it)
# ---------------------------------------------------------------------------
_JS = """<script>
(function(){
  var root = document.documentElement;
  var saved = null;
  try { saved = localStorage.getItem('w3b-theme'); } catch (e) {}
  if (saved) root.setAttribute('data-theme', saved);

  function currentTheme(){
    var attr = root.getAttribute('data-theme');
    if (attr) return attr;
    return (window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches) ? 'dark' : 'light';
  }

  var tbtn = document.getElementById('themeToggle');
  if (tbtn) tbtn.addEventListener('click', function(){
    var next = currentTheme() === 'dark' ? 'light' : 'dark';
    root.setAttribute('data-theme', next);
    try { localStorage.setItem('w3b-theme', next); } catch (e) {}
  });

  var pbtn = document.getElementById('printBtn');
  if (pbtn) pbtn.addEventListener('click', function(){ window.print(); });

  // Collapse / expand individual findings
  document.querySelectorAll('.f-head-btn').forEach(function(btn){
    btn.addEventListener('click', function(){
      var art = btn.closest('.finding');
      var collapsed = art.classList.toggle('collapsed');
      btn.setAttribute('aria-expanded', collapsed ? 'false' : 'true');
    });
  });
  function setAll(collapsed){
    document.querySelectorAll('.finding').forEach(function(a){
      a.classList.toggle('collapsed', collapsed);
      var b = a.querySelector('.f-head-btn');
      if (b) b.setAttribute('aria-expanded', collapsed ? 'false' : 'true');
    });
  }
  var ea = document.getElementById('expandAll'), ca = document.getElementById('collapseAll');
  if (ea) ea.addEventListener('click', function(){ setAll(false); });
  if (ca) ca.addEventListener('click', function(){ setAll(true); });

  // Filtering (text + severity chips)
  var searchInput = document.getElementById('findSearch');
  var countEl = document.getElementById('filterCount');
  var emptyEl = document.getElementById('noMatch');
  var active = { critical:true, high:true, medium:true, low:true };

  function applyFilter(){
    var q = (searchInput && searchInput.value || '').trim().toLowerCase();
    var shown = 0, total = 0;
    document.querySelectorAll('.finding').forEach(function(a){
      total++;
      var sev = a.getAttribute('data-sev');
      var text = a.getAttribute('data-text') || '';
      var ok = active[sev] && (q === '' || text.indexOf(q) > -1);
      a.style.display = ok ? '' : 'none';
      if (ok) shown++;
    });
    if (countEl) countEl.textContent = shown + ' of ' + total;
    if (emptyEl) emptyEl.hidden = shown !== 0;
  }
  document.querySelectorAll('.filter-chip').forEach(function(c){
    c.addEventListener('click', function(){
      var s = c.getAttribute('data-sev');
      active[s] = !active[s];
      c.classList.toggle('off', !active[s]);
      c.setAttribute('aria-pressed', active[s] ? 'true' : 'false');
      applyFilter();
    });
  });
  if (searchInput) searchInput.addEventListener('input', applyFilter);

  // Copy buttons (payload/evidence + permalink)
  function flash(btn){
    var old = btn.textContent;
    btn.classList.add('copied');
    if (btn.classList.contains('copy-btn')) btn.textContent = 'Copied';
    setTimeout(function(){ btn.classList.remove('copied'); if (btn.classList.contains('copy-btn')) btn.textContent = old; }, 1400);
  }
  document.querySelectorAll('[data-copy]').forEach(function(btn){
    btn.addEventListener('click', function(){
      var txt;
      if (btn.getAttribute('data-copy') === 'link') {
        txt = location.href.split('#')[0] + '#' + btn.getAttribute('data-target');
      } else {
        var blk = btn.closest('.f-block');
        var pre = blk && blk.querySelector('pre');
        txt = pre ? pre.innerText : '';
      }
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(txt).then(function(){ flash(btn); });
      }
    });
  });

  // Back to top
  var top = document.getElementById('toTop');
  if (top) {
    window.addEventListener('scroll', function(){ top.classList.toggle('show', window.scrollY > 600); }, { passive:true });
    top.addEventListener('click', function(){ window.scrollTo({ top:0, behavior:'smooth' }); });
  }

  applyFilter();
})();
</script>"""
