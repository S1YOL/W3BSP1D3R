from __future__ import annotations
"""
scanner/reporting/json_report.py
----------------------------------
JSON export for machine-readable results.

Why JSON?
  JSON output enables integration with other tools — SIEM platforms,
  ticketing systems, CI/CD pipelines, or custom dashboards. A professional
  scanner always exports structured data alongside human-readable reports.

Output is pretty-printed (indent=2) for readability in git diffs and
manual review.
"""

import json
import logging
from pathlib import Path

from scanner.reporting.models import ScanSummary

logger = logging.getLogger(__name__)


def write_json_report(summary: ScanSummary, output_path: str) -> Path:
    """
    Write all scan findings to a JSON file.

    Args:
        summary     : Completed ScanSummary object from the scanner.
        output_path : Destination file path (will be created or overwritten).

    Returns:
        Path object pointing to the written file.
    """
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    report_data = {
        "scanner": "W3BSP1D3R",
        "version": "1.0.0",
        "report_type": "vulnerability_scan",
        "summary": {
            "target_url":     summary.target_url,
            "scan_type":      summary.scan_type,
            "started_at":     summary.started_at,
            "finished_at":    summary.finished_at,
            "pages_crawled":  summary.pages_crawled,
            "forms_found":    summary.forms_found,
            "params_tested":  summary.params_tested,
            "total_findings": summary.total_findings,
            "severity_breakdown": {
                "critical": summary.critical_count,
                "high":     summary.high_count,
                "medium":   summary.medium_count,
                "low":      summary.low_count,
            },
        },
        "findings": [f.to_dict() for f in summary.sorted_findings()],
    }

    with path.open("w", encoding="utf-8") as fh:
        json.dump(report_data, fh, indent=2, ensure_ascii=False)

    logger.info("JSON report written to %s", path)
    return path
