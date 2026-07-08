from __future__ import annotations
"""
scanner/reporting/sarif_report.py
-----------------------------------
SARIF (Static Analysis Results Interchange Format) v2.1.0 export.

Why SARIF?
  SARIF is the industry standard for security tool output. It integrates
  natively with:
  - GitHub Advanced Security (Code Scanning alerts)
  - GitLab SAST/DAST dashboards
  - Azure DevOps security centre
  - VS Code SARIF Viewer extension
  - Defect Dojo, OWASP ZAP, and other aggregators

  Adding SARIF output makes W3BSP1D3R a first-class citizen in CI/CD
  security pipelines — not just a standalone scanner.

Spec: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
"""

import json
import logging
from pathlib import Path

from scanner.reporting.models import Finding, ScanSummary, Severity

logger = logging.getLogger(__name__)

# SARIF severity mapping (SARIF uses: error, warning, note, none)
_SARIF_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH:     "error",
    Severity.MEDIUM:   "warning",
    Severity.LOW:      "note",
}

# SARIF security-severity mapping (numeric, used by GitHub)
_SARIF_SECURITY_SEVERITY = {
    Severity.CRITICAL: "9.5",
    Severity.HIGH:     "7.5",
    Severity.MEDIUM:   "5.0",
    Severity.LOW:      "2.0",
}


def write_sarif_report(summary: ScanSummary, output_path: str) -> Path:
    """
    Write scan findings in SARIF v2.1.0 format.

    Args:
        summary     : Completed ScanSummary from the scanner.
        output_path : Destination .sarif file path.

    Returns:
        Path object of the written file.
    """
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    sarif = _build_sarif(summary)

    with path.open("w", encoding="utf-8") as fh:
        json.dump(sarif, fh, indent=2, ensure_ascii=False)

    logger.info("SARIF report written to %s", path)
    return path


def _build_sarif(summary: ScanSummary) -> dict:
    """Construct the full SARIF v2.1.0 JSON structure."""
    rules = []
    results = []
    seen_rule_ids = {}

    for finding in summary.sorted_findings():
        rule_id = _make_rule_id(finding)

        # Register the rule (deduplicated)
        if rule_id not in seen_rule_ids:
            seen_rule_ids[rule_id] = len(rules)
            rules.append(_build_rule(rule_id, finding))

        results.append(_build_result(rule_id, finding))

    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "W3BSP1D3R",
                        "version": "3.0.0-beta",
                        "informationUri": "https://github.com/siyol/web-vuln-scanner",
                        "rules": rules,
                    }
                },
                "results": results,
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "startTimeUtc": summary.started_at,
                        "endTimeUtc": summary.finished_at or summary.started_at,
                    }
                ],
            }
        ],
    }


def _make_rule_id(finding: Finding) -> str:
    """Generate a stable rule ID from the vulnerability type."""
    return finding.vuln_type.lower().replace(" ", "-").replace("(", "").replace(")", "").replace("/", "-")


def _build_rule(rule_id: str, finding: Finding) -> dict:
    """Build a SARIF rule descriptor."""
    return {
        "id": rule_id,
        "name": finding.vuln_type,
        "shortDescription": {
            "text": finding.vuln_type,
        },
        "fullDescription": {
            "text": finding.remediation,
        },
        "defaultConfiguration": {
            "level": _SARIF_LEVEL.get(finding.severity, "warning"),
        },
        "properties": {
            "security-severity": _SARIF_SECURITY_SEVERITY.get(finding.severity, "5.0"),
            # GitHub code-scanning surfaces CWE from an "external/cwe/cwe-NNN" tag.
            "tags": ["security", "web", "vulnerability"] + (
                [f"external/cwe/{finding.cwe.lower()}"] if finding.cwe else []
            ),
            "cwe": finding.cwe or "",
        },
    }


def _build_result(rule_id: str, finding: Finding) -> dict:
    """Build a SARIF result entry for a single finding."""
    result = {
        "ruleId": rule_id,
        "level": _SARIF_LEVEL.get(finding.severity, "warning"),
        "message": {
            "text": (
                f"{finding.vuln_type} found at {finding.url} "
                f"(parameter: {finding.parameter}, method: {finding.method}). "
                f"Evidence: {finding.evidence[:300]}"
            ),
        },
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": finding.url,
                    },
                },
                "properties": {
                    "parameter": finding.parameter,
                    "method": finding.method,
                },
            }
        ],
        "properties": {
            "severity": finding.severity,
            "confidence": finding.confidence,
            "cwe": finding.cwe or "",
            "payload": finding.payload,
            "timestamp": finding.timestamp,
        },
    }

    if finding.remediation:
        result["fixes"] = [
            {
                "description": {
                    "text": finding.remediation,
                },
            }
        ]

    return result
