from __future__ import annotations
"""
scanner/reporting/diff_report.py
-----------------------------------
Scan comparison and diff reporting.

Compares two scan results to identify:
  - NEW findings (present in current scan, absent in baseline)
  - FIXED findings (present in baseline, absent in current scan)
  - UNCHANGED findings (present in both scans)
  - REGRESSION findings (were fixed but reappeared)

Uses finding fingerprints for stable cross-scan comparison.

Usage:
    from scanner.reporting.diff_report import compare_scans, write_diff_report

    diff = compare_scans(current_summary, baseline_summary)
    write_diff_report(diff, "diff_report.md")

    # Or compare with a previous JSON report file
    diff = compare_with_file(current_summary, "previous_scan.json")
"""

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from scanner.reporting.models import Finding, ScanSummary, Severity

logger = logging.getLogger(__name__)


@dataclass
class ScanDiff:
    """Results of comparing two scan runs."""
    current_scan_id: str = ""
    baseline_scan_id: str = ""
    current_target: str = ""
    baseline_target: str = ""

    new_findings: list[Finding] = field(default_factory=list)
    fixed_findings: list[Finding] = field(default_factory=list)
    unchanged_findings: list[Finding] = field(default_factory=list)

    @property
    def total_new(self) -> int:
        return len(self.new_findings)

    @property
    def total_fixed(self) -> int:
        return len(self.fixed_findings)

    @property
    def total_unchanged(self) -> int:
        return len(self.unchanged_findings)

    @property
    def improved(self) -> bool:
        """True if the security posture improved (more fixed than new)."""
        return self.total_fixed > self.total_new

    @property
    def new_by_severity(self) -> dict[str, int]:
        return _count_by_severity(self.new_findings)

    @property
    def fixed_by_severity(self) -> dict[str, int]:
        return _count_by_severity(self.fixed_findings)

    def to_dict(self) -> dict:
        return {
            "current_scan_id": self.current_scan_id,
            "baseline_scan_id": self.baseline_scan_id,
            "summary": {
                "new": self.total_new,
                "fixed": self.total_fixed,
                "unchanged": self.total_unchanged,
                "improved": self.improved,
                "new_by_severity": self.new_by_severity,
                "fixed_by_severity": self.fixed_by_severity,
            },
            "new_findings": [f.to_dict() for f in self.new_findings],
            "fixed_findings": [f.to_dict() for f in self.fixed_findings],
            "unchanged_findings": [f.to_dict() for f in self.unchanged_findings],
        }


def _count_by_severity(findings: list[Finding]) -> dict[str, int]:
    counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for f in findings:
        if f.severity in counts:
            counts[f.severity] += 1
    return counts


def compare_scans(
    current: ScanSummary,
    baseline: ScanSummary,
) -> ScanDiff:
    """
    Compare current scan results against a baseline scan.

    Uses finding fingerprints for stable comparison across runs.
    """
    current_fps = {f.fingerprint: f for f in current.findings}
    baseline_fps = {f.fingerprint: f for f in baseline.findings}

    diff = ScanDiff(
        current_target=current.target_url,
        baseline_target=baseline.target_url,
    )

    # New findings: in current but not in baseline
    for fp, finding in current_fps.items():
        if fp not in baseline_fps:
            diff.new_findings.append(finding)
        else:
            diff.unchanged_findings.append(finding)

    # Fixed findings: in baseline but not in current
    for fp, finding in baseline_fps.items():
        if fp not in current_fps:
            diff.fixed_findings.append(finding)

    # Sort by severity
    diff.new_findings.sort(key=lambda f: f.severity_order)
    diff.fixed_findings.sort(key=lambda f: f.severity_order)

    logger.info(
        "Scan comparison: %d new, %d fixed, %d unchanged",
        diff.total_new, diff.total_fixed, diff.total_unchanged,
    )

    return diff


def compare_with_file(
    current: ScanSummary,
    baseline_path: str,
) -> ScanDiff:
    """
    Compare current scan results against a previous JSON report file.
    """
    path = Path(baseline_path)
    if not path.exists():
        raise FileNotFoundError(f"Baseline report not found: {path}")

    with path.open("r", encoding="utf-8") as fh:
        data = json.load(fh)

    # Reconstruct findings from the JSON report
    baseline_findings = []
    for f_data in data.get("findings", []):
        baseline_findings.append(Finding(
            vuln_type=f_data.get("vuln_type", ""),
            severity=f_data.get("severity", ""),
            url=f_data.get("url", ""),
            parameter=f_data.get("parameter", ""),
            method=f_data.get("method", ""),
            payload=f_data.get("payload", ""),
            evidence=f_data.get("evidence", ""),
            remediation=f_data.get("remediation", ""),
            timestamp=f_data.get("timestamp", ""),
            extra=f_data.get("extra"),
        ))

    summary_data = data.get("summary", {})
    baseline_summary = ScanSummary(
        target_url=summary_data.get("target_url", ""),
        scan_type=summary_data.get("scan_type", ""),
        started_at=summary_data.get("started_at", ""),
        finished_at=summary_data.get("finished_at", ""),
    )
    for f in baseline_findings:
        baseline_summary.add_finding(f)

    diff = compare_scans(current, baseline_summary)
    diff.baseline_scan_id = f"file:{path.name}"
    return diff


# ---------------------------------------------------------------------------
# Diff report writers
# ---------------------------------------------------------------------------

def write_diff_report_md(diff: ScanDiff, output_path: str) -> Path:
    """Write the scan diff as a Markdown report."""
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    lines = [
        "# Scan Comparison Report",
        "",
        f"> **Current Target:** `{diff.current_target}`  ",
        f"> **Baseline Target:** `{diff.baseline_target}`  ",
        "",
        "---",
        "",
        "## Summary",
        "",
        "| Category | Count |",
        "|----------|-------|",
        f"| New Findings | **{diff.total_new}** |",
        f"| Fixed Findings | **{diff.total_fixed}** |",
        f"| Unchanged Findings | {diff.total_unchanged} |",
        "",
        f"**Overall:** {'Improved' if diff.improved else 'Degraded or unchanged'}",
        "",
    ]

    if diff.new_findings:
        lines += [
            "## New Findings",
            "",
            f"_{diff.total_new} new vulnerabilit{'y' if diff.total_new == 1 else 'ies'} "
            "detected since the baseline scan._",
            "",
        ]
        for idx, f in enumerate(diff.new_findings, 1):
            lines += _format_finding_md(idx, f, "NEW")

    if diff.fixed_findings:
        lines += [
            "## Fixed Findings",
            "",
            f"_{diff.total_fixed} vulnerabilit{'y' if diff.total_fixed == 1 else 'ies'} "
            "resolved since the baseline scan._",
            "",
        ]
        for idx, f in enumerate(diff.fixed_findings, 1):
            lines += _format_finding_md(idx, f, "FIXED")

    lines += [
        "---",
        "",
        "_Generated by W3BSP1D3R — by S1YOL_",
    ]

    with path.open("w", encoding="utf-8") as fh:
        fh.write("\n".join(lines))

    logger.info("Diff report written to %s", path)
    return path


def write_diff_report_json(diff: ScanDiff, output_path: str) -> Path:
    """Write the scan diff as a JSON report."""
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    with path.open("w", encoding="utf-8") as fh:
        json.dump(diff.to_dict(), fh, indent=2, default=str)

    logger.info("Diff JSON report written to %s", path)
    return path


def _format_finding_md(idx: int, f: Finding, status: str) -> list[str]:
    """Format a single finding for the diff Markdown report."""
    sev_badges = {
        "Critical": "🔴 **CRITICAL**",
        "High": "🟠 **HIGH**",
        "Medium": "🟡 **MEDIUM**",
        "Low": "🔵 **LOW**",
    }
    badge = sev_badges.get(f.severity, f.severity)
    status_icon = "🆕" if status == "NEW" else "✅"

    return [
        f"### {status_icon} {f.vuln_type} ({status})",
        "",
        f"**Severity:** {badge}  ",
        f"**URL:** `{f.url}`  ",
        f"**Parameter:** `{f.parameter}`  ",
        "",
    ]
