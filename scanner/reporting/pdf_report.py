from __future__ import annotations
"""
scanner/reporting/pdf_report.py
---------------------------------
PDF report generator for executive-friendly vulnerability reports.

Uses fpdf2 (a lightweight pure-Python PDF library) to produce
professional reports with:
  - Branded cover page with W3BSP1D3R identity
  - Executive summary with severity statistics
  - Detailed findings with payloads and remediation
  - Colour-coded severity indicators
  - Print-optimised layout

Requires: pip install fpdf2

Usage:
    from scanner.reporting.pdf_report import write_pdf_report
    path = write_pdf_report(summary, "scan_report.pdf")
"""

import logging
from pathlib import Path
from typing import Optional

from scanner.reporting.models import Finding, ScanSummary, Severity

logger = logging.getLogger(__name__)

# Severity → RGB colour mapping
_SEV_COLORS = {
    Severity.CRITICAL: (220, 38, 38),     # Red
    Severity.HIGH:     (234, 88, 12),      # Orange
    Severity.MEDIUM:   (202, 138, 4),      # Amber
    Severity.LOW:      (37, 99, 235),      # Blue
}

# Brand colours
_BRAND_RED = (204, 0, 0)
_BRAND_DARK = (10, 10, 15)
_BRAND_GREY = (100, 100, 110)
_BRAND_LIGHT = (224, 224, 232)


def write_pdf_report(summary: ScanSummary, output_path: str) -> Path:
    """
    Generate a professional PDF vulnerability report.

    Args:
        summary     : Completed ScanSummary from the scanner.
        output_path : Destination .pdf file path.

    Returns:
        Path to the written PDF file.

    Raises:
        ImportError if fpdf2 is not installed.
    """
    try:
        from fpdf import FPDF
    except ImportError:
        raise ImportError(
            "PDF report generation requires fpdf2. "
            "Install with: pip install fpdf2"
        )

    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    pdf = _W3BSP1D3RPDF()
    pdf.set_auto_page_break(auto=True, margin=20)

    # Cover page
    _add_cover_page(pdf, summary)

    # Executive summary
    _add_executive_summary(pdf, summary)

    # Findings
    _add_findings(pdf, summary)

    # Disclaimer page
    _add_disclaimer(pdf)

    # Write output
    pdf.output(str(path))
    logger.info("PDF report written to %s", path)
    return path


class _W3BSP1D3RPDF:
    """Wrapper around FPDF with helper methods for the report."""

    def __init__(self):
        from fpdf import FPDF
        self._pdf = FPDF()
        self._pdf.set_margins(15, 15, 15)

    def __getattr__(self, name):
        return getattr(self._pdf, name)

    def output(self, path: str):
        self._pdf.output(path)


def _add_cover_page(pdf: _W3BSP1D3RPDF, summary: ScanSummary) -> None:
    """Add a branded cover page."""
    pdf.add_page()

    # Dark header band
    pdf.set_fill_color(*_BRAND_DARK)
    pdf.rect(0, 0, 210, 100, 'F')

    # Red accent line
    pdf.set_fill_color(*_BRAND_RED)
    pdf.rect(0, 100, 210, 3, 'F')

    # Brand name
    pdf.set_font("Helvetica", "B", 36)
    pdf.set_text_color(255, 255, 255)
    pdf.ln(25)
    pdf.cell(0, 18, "W3BSP1D3R", new_x="LMARGIN", new_y="NEXT", align="C")

    # Subtitle
    pdf.set_font("Helvetica", "", 13)
    pdf.set_text_color(*_BRAND_LIGHT)
    pdf.cell(0, 8, "Web Vulnerability Scanner", new_x="LMARGIN", new_y="NEXT", align="C")

    # Version
    pdf.set_font("Courier", "B", 9)
    pdf.set_text_color(*_BRAND_RED)
    pdf.cell(0, 8, "v3.0.0-beta", new_x="LMARGIN", new_y="NEXT", align="C")

    # Report title
    pdf.ln(25)
    pdf.set_font("Helvetica", "B", 22)
    pdf.set_text_color(30, 30, 30)
    pdf.cell(0, 12, "Scan Report", new_x="LMARGIN", new_y="NEXT", align="C")

    # Thin divider
    pdf.ln(5)
    pdf.set_draw_color(*_BRAND_RED)
    pdf.set_line_width(0.5)
    pdf.line(70, pdf.get_y(), 140, pdf.get_y())

    # Scan metadata
    pdf.ln(12)
    pdf.set_text_color(40, 40, 40)

    meta = [
        ("Target", summary.target_url),
        ("Scan Type", summary.scan_type),
        ("Started", summary.started_at),
        ("Finished", summary.finished_at),
        ("Total Findings", str(summary.total_findings)),
    ]

    for label, value in meta:
        pdf.set_font("Helvetica", "B", 10)
        pdf.set_text_color(*_BRAND_GREY)
        pdf.cell(45, 7, f"{label}:", align="R")
        pdf.set_font("Helvetica", "", 10)
        pdf.set_text_color(30, 30, 30)
        pdf.cell(5, 7, "")
        # Truncate long values
        display_val = value[:80] + "..." if len(value) > 80 else value
        pdf.cell(0, 7, display_val, new_x="LMARGIN", new_y="NEXT")

    # Severity summary boxes at bottom
    pdf.ln(15)
    _draw_severity_boxes(pdf, summary)

    # Footer note
    pdf.ln(20)
    pdf.set_font("Helvetica", "I", 8)
    pdf.set_text_color(150, 150, 150)
    pdf.cell(0, 5, "by S1YOL", new_x="LMARGIN", new_y="NEXT", align="C")


def _draw_severity_boxes(pdf: _W3BSP1D3RPDF, summary: ScanSummary) -> None:
    """Draw severity count boxes on the cover page."""
    boxes = [
        ("CRITICAL", summary.critical_count, _SEV_COLORS[Severity.CRITICAL]),
        ("HIGH", summary.high_count, _SEV_COLORS[Severity.HIGH]),
        ("MEDIUM", summary.medium_count, _SEV_COLORS[Severity.MEDIUM]),
        ("LOW", summary.low_count, _SEV_COLORS[Severity.LOW]),
    ]

    box_width = 40
    gap = 5
    total_width = (box_width * 4) + (gap * 3)
    start_x = (210 - total_width) / 2
    y = pdf.get_y()

    for i, (label, count, color) in enumerate(boxes):
        x = start_x + i * (box_width + gap)

        # Box background
        pdf.set_fill_color(*color)
        pdf.rect(x, y, box_width, 22, 'F')

        # Count
        pdf.set_xy(x, y + 2)
        pdf.set_font("Helvetica", "B", 16)
        pdf.set_text_color(255, 255, 255)
        pdf.cell(box_width, 10, str(count), align="C")

        # Label
        pdf.set_xy(x, y + 12)
        pdf.set_font("Helvetica", "", 7)
        pdf.cell(box_width, 8, label, align="C")

    pdf.set_y(y + 25)


def _add_executive_summary(pdf: _W3BSP1D3RPDF, summary: ScanSummary) -> None:
    """Add executive summary with statistics."""
    pdf.add_page()

    # Section header with red accent
    pdf.set_fill_color(*_BRAND_RED)
    pdf.rect(15, pdf.get_y(), 3, 10, 'F')
    pdf.set_font("Helvetica", "B", 16)
    pdf.set_text_color(30, 30, 30)
    pdf.cell(8, 10, "")
    pdf.cell(0, 10, "Executive Summary", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(5)

    # Stats table with alternating rows
    stats = [
        ("Pages Crawled", str(summary.pages_crawled)),
        ("Forms Discovered", str(summary.forms_found)),
        ("Parameters Tested", str(summary.params_tested)),
        ("Total Findings", str(summary.total_findings)),
    ]

    for i, (label, value) in enumerate(stats):
        if i % 2 == 0:
            pdf.set_fill_color(245, 245, 248)
        else:
            pdf.set_fill_color(255, 255, 255)
        pdf.set_font("Helvetica", "", 10)
        pdf.set_text_color(*_BRAND_GREY)
        pdf.cell(70, 8, label, border=0, fill=True)
        pdf.set_font("Helvetica", "B", 10)
        pdf.set_text_color(30, 30, 30)
        pdf.cell(0, 8, value, border=0, fill=True, new_x="LMARGIN", new_y="NEXT")

    pdf.ln(10)

    # Severity breakdown header
    pdf.set_fill_color(*_BRAND_RED)
    pdf.rect(15, pdf.get_y(), 3, 8, 'F')
    pdf.set_font("Helvetica", "B", 13)
    pdf.set_text_color(30, 30, 30)
    pdf.cell(8, 8, "")
    pdf.cell(0, 8, "Severity Breakdown", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(5)

    breakdown = [
        ("CRITICAL", summary.critical_count, _SEV_COLORS[Severity.CRITICAL]),
        ("HIGH", summary.high_count, _SEV_COLORS[Severity.HIGH]),
        ("MEDIUM", summary.medium_count, _SEV_COLORS[Severity.MEDIUM]),
        ("LOW", summary.low_count, _SEV_COLORS[Severity.LOW]),
    ]

    total = max(summary.total_findings, 1)

    for label, count, color in breakdown:
        # Severity badge
        pdf.set_fill_color(*color)
        pdf.set_text_color(255, 255, 255)
        pdf.set_font("Helvetica", "B", 8)
        pdf.cell(22, 7, label, fill=True)

        # Count
        pdf.set_text_color(30, 30, 30)
        pdf.set_font("Courier", "B", 10)
        pdf.cell(12, 7, str(count), align="C")

        # Bar
        bar_width = int((count / total) * 100)
        if bar_width > 0:
            pdf.set_fill_color(*color)
            pdf.cell(bar_width, 7, "", fill=True)

        pdf.ln(9)

    pdf.set_text_color(0, 0, 0)


def _add_findings(pdf: _W3BSP1D3RPDF, summary: ScanSummary) -> None:
    """Add detailed finding cards."""
    findings = summary.sorted_findings()
    if not findings:
        pdf.ln(10)
        pdf.set_font("Helvetica", "B", 12)
        pdf.set_text_color(34, 197, 94)
        pdf.cell(0, 10, "No vulnerabilities detected.", new_x="LMARGIN", new_y="NEXT")
        return

    pdf.add_page()

    # Section header
    pdf.set_fill_color(*_BRAND_RED)
    pdf.rect(15, pdf.get_y(), 3, 10, 'F')
    pdf.set_font("Helvetica", "B", 16)
    pdf.set_text_color(30, 30, 30)
    pdf.cell(8, 10, "")
    pdf.cell(0, 10, f"Findings ({len(findings)})", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(5)

    for idx, finding in enumerate(findings, 1):
        _add_finding_card(pdf, idx, finding)


def _add_finding_card(pdf: _W3BSP1D3RPDF, idx: int, finding: Finding) -> None:
    """Add a single finding to the PDF."""
    color = _SEV_COLORS.get(finding.severity, (100, 100, 100))

    # Check if we need a new page
    if pdf.get_y() > 220:
        pdf.add_page()

    # Finding header — coloured left border + severity badge
    y_start = pdf.get_y()
    pdf.set_fill_color(*color)
    pdf.rect(15, y_start, 3, 8, 'F')

    pdf.set_text_color(255, 255, 255)
    pdf.set_font("Helvetica", "B", 9)

    # Severity badge
    badge_x = 20
    pdf.set_xy(badge_x, y_start)
    pdf.cell(20, 8, finding.severity.upper(), fill=True)

    # Finding title
    pdf.set_text_color(30, 30, 30)
    pdf.set_font("Helvetica", "B", 10)
    pdf.cell(5, 8, "")
    pdf.cell(0, 8, f"#{idx}  {finding.vuln_type}", new_x="LMARGIN", new_y="NEXT")

    # Grey content area
    pdf.set_fill_color(248, 248, 250)

    # Metadata
    details = [
        ("URL", finding.url),
        ("Parameter", finding.parameter),
        ("Method", finding.method),
    ]
    for label, value in details:
        pdf.set_font("Helvetica", "B", 8)
        pdf.set_text_color(*_BRAND_GREY)
        pdf.cell(22, 5, f"{label}:")
        pdf.set_font("Courier", "", 8)
        pdf.set_text_color(40, 40, 40)
        display_val = value[:95] + "..." if len(value) > 95 else value
        pdf.cell(0, 5, display_val, new_x="LMARGIN", new_y="NEXT")

    # Payload
    pdf.set_font("Helvetica", "B", 8)
    pdf.set_text_color(*_BRAND_GREY)
    pdf.cell(0, 5, "Payload:", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Courier", "", 7)
    pdf.set_text_color(*_BRAND_RED)
    payload_display = finding.payload[:130] + "..." if len(finding.payload) > 130 else finding.payload
    pdf.multi_cell(0, 4, payload_display)

    # Evidence
    pdf.set_font("Helvetica", "B", 8)
    pdf.set_text_color(*_BRAND_GREY)
    pdf.cell(0, 5, "Evidence:", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", "I", 7)
    pdf.set_text_color(80, 80, 80)
    evidence_display = finding.evidence[:220] + "..." if len(finding.evidence) > 220 else finding.evidence
    pdf.multi_cell(0, 4, evidence_display)

    # Remediation
    pdf.set_font("Helvetica", "B", 8)
    pdf.set_text_color(*_BRAND_GREY)
    pdf.cell(0, 5, "Remediation:", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", "", 7)
    pdf.set_text_color(22, 120, 60)
    pdf.multi_cell(0, 4, finding.remediation[:300])
    pdf.set_text_color(0, 0, 0)

    # Separator line
    pdf.ln(3)
    pdf.set_draw_color(220, 220, 225)
    pdf.set_line_width(0.2)
    pdf.line(15, pdf.get_y(), 195, pdf.get_y())
    pdf.ln(4)


def _add_disclaimer(pdf: _W3BSP1D3RPDF) -> None:
    """Add legal disclaimer page."""
    pdf.add_page()

    pdf.set_fill_color(*_BRAND_RED)
    pdf.rect(15, pdf.get_y(), 3, 8, 'F')
    pdf.set_font("Helvetica", "B", 14)
    pdf.set_text_color(30, 30, 30)
    pdf.cell(8, 8, "")
    pdf.cell(0, 8, "Legal Disclaimer", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(8)

    pdf.set_font("Helvetica", "", 9)
    pdf.set_text_color(80, 80, 80)
    pdf.multi_cell(0, 5,
        "CONFIDENTIAL - This report contains sensitive security information. "
        "Unauthorised distribution is strictly prohibited.\n\n"
        "This tool is provided for authorised security testing and educational "
        "purposes only. You must only scan systems you own or have explicit "
        "written permission to test.\n\n"
        "Unauthorised scanning is a criminal offence under the Computer Fraud "
        "and Abuse Act (CFAA, 18 U.S.C. 1030) and equivalent legislation "
        "worldwide.\n\n"
        "The author assumes no responsibility or liability for any misuse, "
        "damage, or legal consequences arising from the use of this software. "
        "By using W3BSP1D3R you acknowledge that you do so entirely at your "
        "own risk."
    )

    pdf.ln(15)
    pdf.set_font("Helvetica", "B", 10)
    pdf.set_text_color(*_BRAND_RED)
    pdf.cell(0, 8, "W3BSP1D3R v3.0.0-beta", new_x="LMARGIN", new_y="NEXT", align="C")
    pdf.set_font("Helvetica", "", 9)
    pdf.set_text_color(*_BRAND_GREY)
    pdf.cell(0, 6, "by S1YOL", new_x="LMARGIN", new_y="NEXT", align="C")
