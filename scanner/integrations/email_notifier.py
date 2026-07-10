from __future__ import annotations
"""
scanner/integrations/email_notifier.py
-----------------------------------------
SMTP email notifications for scan completion.

Sends a formatted HTML email with scan summary and severity breakdown
when a scan finishes. Supports TLS/STARTTLS and authentication.

Usage:
    from scanner.integrations.email_notifier import EmailNotifier, EmailConfig

    config = EmailConfig(
        enabled=True,
        smtp_host="smtp.gmail.com",
        smtp_port=587,
        username="scanner@company.com",
        password="app-password",
        from_addr="scanner@company.com",
        to_addrs=["security-team@company.com"],
    )

    notifier = EmailNotifier(config)
    notifier.send_scan_report(summary, scan_id="abc123")
"""

import logging
import smtplib
import ssl
from dataclasses import dataclass, field
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Optional

from scanner.reporting.models import ScanSummary

logger = logging.getLogger(__name__)


@dataclass
class EmailConfig:
    """Email notification configuration."""
    enabled: bool = False
    smtp_host: str = ""
    smtp_port: int = 587
    use_tls: bool = True
    username: Optional[str] = None
    password: Optional[str] = None
    from_addr: str = ""
    to_addrs: list[str] = field(default_factory=list)
    subject_prefix: str = "[W3BSP1D3R]"
    on_findings_only: bool = False


class EmailNotifier:
    """Sends scan completion emails via SMTP."""

    def __init__(self, config: EmailConfig) -> None:
        self.config = config

    def send_scan_report(
        self,
        summary: ScanSummary,
        scan_id: str = "",
    ) -> bool:
        """
        Send a scan report email. Returns True on success.
        Failures are logged but never raised.
        """
        if not self.config.enabled:
            return False

        if not self.config.to_addrs:
            logger.warning("Email notification skipped: no recipients configured")
            return False

        if self.config.on_findings_only and summary.total_findings == 0:
            logger.debug("No findings — skipping email notification")
            return False

        subject = self._build_subject(summary)
        html_body = self._build_html(summary, scan_id)

        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = self.config.from_addr
        msg["To"] = ", ".join(self.config.to_addrs)
        msg.attach(MIMEText(self._build_plaintext(summary, scan_id), "plain"))
        msg.attach(MIMEText(html_body, "html"))

        try:
            if self.config.use_tls:
                context = ssl.create_default_context()
                with smtplib.SMTP(self.config.smtp_host, self.config.smtp_port, timeout=30) as server:
                    server.starttls(context=context)
                    if self.config.username and self.config.password:
                        server.login(self.config.username, self.config.password)
                    server.sendmail(self.config.from_addr, self.config.to_addrs, msg.as_string())
            else:
                with smtplib.SMTP(self.config.smtp_host, self.config.smtp_port, timeout=30) as server:
                    if self.config.username and self.config.password:
                        server.login(self.config.username, self.config.password)
                    server.sendmail(self.config.from_addr, self.config.to_addrs, msg.as_string())

            logger.info("Scan report emailed to %s", ", ".join(self.config.to_addrs))
            return True

        except Exception as exc:
            logger.warning("Email notification failed: %s", exc)
            return False

    def _build_subject(self, summary: ScanSummary) -> str:
        prefix = self.config.subject_prefix
        if summary.total_findings == 0:
            return f"{prefix} Scan Clean — {summary.target_url}"
        sev = "CRITICAL" if summary.critical_count else (
            "HIGH" if summary.high_count else "MEDIUM"
        )
        return f"{prefix} {summary.total_findings} Finding(s) [{sev}] — {summary.target_url}"

    def _build_plaintext(self, summary: ScanSummary, scan_id: str) -> str:
        return (
            f"W3BSP1D3R Scan Report\n"
            f"{'=' * 40}\n"
            f"Target:   {summary.target_url}\n"
            f"Scan ID:  {scan_id}\n"
            f"Type:     {summary.scan_type}\n"
            f"Started:  {summary.started_at}\n"
            f"Finished: {summary.finished_at}\n\n"
            f"Findings: {summary.total_findings}\n"
            f"  Critical: {summary.critical_count}\n"
            f"  High:     {summary.high_count}\n"
            f"  Medium:   {summary.medium_count}\n"
            f"  Low:      {summary.low_count}\n\n"
            f"Pages:  {summary.pages_crawled}\n"
            f"Forms:  {summary.forms_found}\n"
            f"Params: {summary.params_tested}\n"
        )

    def _build_html(self, summary: ScanSummary, scan_id: str) -> str:
        sev_colors = {"Critical": "#dc2626", "High": "#ea580c",
                      "Medium": "#ca8a04", "Low": "#2563eb"}

        findings_rows = ""
        for f in summary.sorted_findings()[:20]:  # Cap at 20 in email
            color = sev_colors.get(f.severity, "#666")
            findings_rows += (
                f'<tr><td style="color:{color};font-weight:bold">{f.severity}</td>'
                f'<td>{f.vuln_type}</td>'
                f'<td><code>{f.parameter}</code></td>'
                f'<td style="font-size:12px">{f.url[:80]}</td></tr>\n'
            )

        if summary.total_findings > 20:
            findings_rows += f'<tr><td colspan="4"><em>... and {summary.total_findings - 20} more</em></td></tr>'

        return f"""
        <div style="font-family:sans-serif;max-width:600px;margin:0 auto">
            <h2 style="color:#cc0000">W3BSP1D3R Scan Report</h2>
            <table style="width:100%;border-collapse:collapse;margin:16px 0">
                <tr><td style="padding:4px 8px;color:#666">Target</td><td><code>{summary.target_url}</code></td></tr>
                <tr><td style="padding:4px 8px;color:#666">Scan ID</td><td><code>{scan_id}</code></td></tr>
                <tr><td style="padding:4px 8px;color:#666">Type</td><td>{summary.scan_type}</td></tr>
                <tr><td style="padding:4px 8px;color:#666">Duration</td><td>{summary.started_at} → {summary.finished_at}</td></tr>
            </table>
            <table style="width:100%;text-align:center;margin:16px 0">
                <tr>
                    <td style="background:#fee2e2;padding:12px;border-radius:8px">
                        <div style="font-size:24px;font-weight:bold;color:#dc2626">{summary.critical_count}</div>
                        <div style="font-size:12px;color:#666">Critical</div>
                    </td>
                    <td style="background:#fff0e6;padding:12px;border-radius:8px">
                        <div style="font-size:24px;font-weight:bold;color:#ea580c">{summary.high_count}</div>
                        <div style="font-size:12px;color:#666">High</div>
                    </td>
                    <td style="background:#fef9c3;padding:12px;border-radius:8px">
                        <div style="font-size:24px;font-weight:bold;color:#ca8a04">{summary.medium_count}</div>
                        <div style="font-size:12px;color:#666">Medium</div>
                    </td>
                    <td style="background:#dbeafe;padding:12px;border-radius:8px">
                        <div style="font-size:24px;font-weight:bold;color:#2563eb">{summary.low_count}</div>
                        <div style="font-size:12px;color:#666">Low</div>
                    </td>
                </tr>
            </table>
            {"<h3>Top Findings</h3><table style='width:100%;border-collapse:collapse;font-size:13px'><tr style='background:#f5f5f5'><th style='text-align:left;padding:4px'>Severity</th><th style='text-align:left;padding:4px'>Type</th><th style='text-align:left;padding:4px'>Param</th><th style='text-align:left;padding:4px'>URL</th></tr>" + findings_rows + "</table>" if findings_rows else "<p style='color:green'>No vulnerabilities detected.</p>"}
            <hr style="margin:24px 0;border:1px solid #eee">
            <p style="font-size:11px;color:#999">Generated by W3BSP1D3R — by S1YOL</p>
        </div>
        """
