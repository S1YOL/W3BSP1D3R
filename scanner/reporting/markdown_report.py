from __future__ import annotations
"""
scanner/reporting/markdown_report.py
--------------------------------------
Generates a professional Markdown vulnerability report.

The report is structured as:
  1. Executive Summary — stats + severity breakdown table
  2. Findings — one section per vulnerability, sorted by severity
  3. Remediation Summary — consolidated fix guidance
  4. Disclaimer

Markdown was chosen as the primary human-readable format because:
  - It renders beautifully on GitHub, GitLab, and most bug-bounty platforms
  - It can be converted to PDF/HTML easily with pandoc
  - It's diff-friendly for version-controlled reports
"""

import logging
from datetime import datetime
from pathlib import Path

from scanner.reporting.models import Finding, ScanSummary, Severity

logger = logging.getLogger(__name__)


def _overall_risk(summary: ScanSummary) -> tuple[str, str]:
    """Derive a single overall risk rating from the highest severity present."""
    if summary.critical_count:
        return "CRITICAL", "🔴"
    if summary.high_count:
        return "HIGH", "🟠"
    if summary.medium_count:
        return "MEDIUM", "🟡"
    if summary.low_count:
        return "LOW", "🔵"
    return "INFORMATIONAL", "⚪"


def _scan_duration(summary: ScanSummary) -> str:
    """Human-readable scan duration from the ISO timestamps."""
    try:
        started = datetime.fromisoformat(summary.started_at)
        finished = datetime.fromisoformat(summary.finished_at)
        secs = (finished - started).total_seconds()
        if secs < 60:
            return f"{secs:.1f}s"
        mins, rem = divmod(int(secs), 60)
        return f"{mins}m {rem}s"
    except (ValueError, TypeError):
        return "N/A"


def _confidence_counts(summary: ScanSummary) -> dict[str, int]:
    counts = {"Certain": 0, "Firm": 0, "Tentative": 0}
    for f in summary.findings:
        counts[f.confidence] = counts.get(f.confidence, 0) + 1
    return counts

# Severity → Markdown badge text (GitHub-flavoured Markdown doesn't support
# coloured text natively, so we use badge-style labels as a workaround)
_SEV_BADGE = {
    Severity.CRITICAL: "🔴 **CRITICAL**",
    Severity.HIGH:     "🟠 **HIGH**",
    Severity.MEDIUM:   "🟡 **MEDIUM**",
    Severity.LOW:      "🔵 **LOW**",
}


def write_markdown_report(summary: ScanSummary, output_path: str) -> Path:
    """
    Write the full Markdown vulnerability report.

    Args:
        summary     : Completed ScanSummary from the scanner.
        output_path : Destination .md file path.

    Returns:
        Path object of the written report file.
    """
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    lines = []
    lines += _header(summary)
    lines += _executive_summary(summary)
    lines += _findings_section(summary)
    lines += _remediation_summary(summary)
    lines += _disclaimer()

    with path.open("w", encoding="utf-8") as fh:
        fh.write("\n".join(lines))

    logger.info("Markdown report written to %s", path)
    return path


# ---------------------------------------------------------------------------
# Section builders
# ---------------------------------------------------------------------------

def _header(summary: ScanSummary) -> list[str]:
    return [
        "# W3BSP1D3R — Scan Report",
        "",
        "```",
        "  W3BSP1D3R  |  Web Vulnerability Scanner  |  v3.0.0-beta  |  by S1YOL",
        "```",
        "",
        "| | |",
        "|---|---|",
        f"| **Target** | `{summary.target_url}` |",
        f"| **Scan Type** | {summary.scan_type} |",
        f"| **Started** | {summary.started_at} |",
        f"| **Finished** | {summary.finished_at} |",
        f"| **Duration** | {_scan_duration(summary)} |",
        "",
        "---",
        "",
    ]


def _executive_summary(summary: ScanSummary) -> list[str]:
    risk, risk_icon = _overall_risk(summary)
    conf = _confidence_counts(summary)
    lines = [
        "## Executive Summary",
        "",
        f"> ### {risk_icon} Overall Risk Rating: **{risk}**",
        "",
        (
            f"This assessment tested **{summary.params_tested}** parameter(s) across "
            f"**{summary.pages_crawled}** page(s) and identified "
            f"**{summary.total_findings}** finding(s): "
            f"{summary.critical_count} critical, {summary.high_count} high, "
            f"{summary.medium_count} medium, {summary.low_count} low."
        ),
        "",
        "| Metric | Value |",
        "|--------|-------|",
        f"| Pages Crawled | {summary.pages_crawled} |",
        f"| Forms Discovered | {summary.forms_found} |",
        f"| Parameters Tested | {summary.params_tested} |",
        f"| Total Findings | **{summary.total_findings}** |",
        "",
        "### Severity Breakdown",
        "",
        "| Severity | Count | Risk |",
        "|----------|-------|------|",
        f"| {_SEV_BADGE[Severity.CRITICAL]} | {summary.critical_count} | Immediate exploitation risk — database compromise, RCE, auth bypass |",
        f"| {_SEV_BADGE[Severity.HIGH]} | {summary.high_count} | Significant impact — session hijack, data exfiltration |",
        f"| {_SEV_BADGE[Severity.MEDIUM]} | {summary.medium_count} | Moderate risk — requires additional conditions to exploit |",
        f"| {_SEV_BADGE[Severity.LOW]} | {summary.low_count} | Low impact — informational, defence-in-depth improvements |",
        "",
        "### Detection Confidence",
        "",
        "_How certain each finding is. Prioritise **Certain** findings; manually "
        "review **Tentative** ones before acting._",
        "",
        "| Confidence | Count | Meaning |",
        "|------------|-------|---------|",
        f"| Certain | {conf.get('Certain', 0)} | Deterministic proof (e.g. reflected payload, DB error) |",
        f"| Firm | {conf.get('Firm', 0)} | Strong heuristic, confirmed with a second request |",
        f"| Tentative | {conf.get('Tentative', 0)} | Heuristic only — manual verification advised |",
        "",
        "---",
        "",
    ]
    return lines


def _findings_section(summary: ScanSummary) -> list[str]:
    findings = summary.sorted_findings()
    if not findings:
        return [
            "## Findings",
            "",
            "> ✅ No vulnerabilities were detected during this scan.",
            "",
            "---",
            "",
        ]

    lines = [
        "## Findings",
        "",
        f"_{len(findings)} vulnerabilit{'y' if len(findings) == 1 else 'ies'} found, "
        f"sorted by severity._",
        "",
    ]

    for idx, finding in enumerate(findings, start=1):
        lines += _single_finding(idx, finding)

    lines += ["---", ""]
    return lines


def _single_finding(idx: int, f: Finding) -> list[str]:
    badge = _SEV_BADGE.get(f.severity, f.severity)
    owasp = f.owasp_category
    classification = f"CWE: `{f.cwe or 'N/A'}`"
    if owasp:
        classification += f" · OWASP: `{owasp['id']} {owasp['name']}`"
    return [
        f"### Finding #{idx} — {f.vuln_type}",
        "",
        f"**Severity:** {badge}  ",
        f"**Confidence:** {f.confidence}  ",
        f"**URL:** `{f.url}`  ",
        f"**Parameter:** `{f.parameter}`  ",
        f"**Method:** `{f.method}`  ",
        f"**Classification:** {classification}  ",
        f"**Timestamp:** {f.timestamp}  ",
        "",
        "#### Proof-of-Concept Payload",
        "",
        "```",
        f.payload,
        "```",
        "",
        "#### Evidence",
        "",
        f"> {f.evidence}",
        "",
        "#### Remediation",
        "",
        f"> {f.remediation}",
        "",
        "---",
        "",
    ]


def _remediation_summary(summary: ScanSummary) -> list[str]:
    if not summary.findings:
        return []

    # Deduplicate remediation strings
    seen: set[str] = set()
    unique_remediations: list[tuple[str, str]] = []
    for f in summary.sorted_findings():
        if f.remediation not in seen:
            seen.add(f.remediation)
            unique_remediations.append((f.vuln_type, f.remediation))

    lines = [
        "## Remediation Summary",
        "",
        "The following fixes are recommended, grouped by vulnerability type:",
        "",
    ]
    for vuln_type, remediation in unique_remediations:
        lines += [
            f"### {vuln_type}",
            "",
            remediation,
            "",
        ]
    lines += ["---", ""]
    return lines


def _disclaimer() -> list[str]:
    return [
        "## Legal Disclaimer",
        "",
        "> **⚠️ AUTHORISED TESTING ONLY**  ",
        "> This report was generated by an automated vulnerability scanner.  ",
        "> The scanner MUST only be used against applications you own or have  ",
        "> **explicit written permission** to test.  ",
        "> Unauthorised scanning is illegal under the Computer Fraud and Abuse Act  ",
        "> (CFAA, 18 U.S.C. § 1030) and equivalent laws in other jurisdictions.  ",
        "> I AM NOT RESPONSIBLE FOR ANYONE USING THIS APP. "
        "Scanning without authorization is a federal crime under CFAA (18 U.S.C. § 1030).  ",
        "",
        "_Report generated by [W3BSP1D3R](https://github.com/siyol/web-vuln-scanner) — by S1YOL_",
        "",
    ]
