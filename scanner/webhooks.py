from __future__ import annotations
"""
scanner/webhooks.py
---------------------
Webhook notifications for scan completion.

Sends formatted notifications to Slack, Microsoft Teams, Discord,
and generic webhook endpoints when a scan finishes.

Each platform has its own message format:
  - Slack:   Block Kit JSON (rich formatting with severity colours)
  - Teams:   Adaptive Card (MessageCard format)
  - Discord: Embed object with colour-coded severity
  - Generic: JSON POST with scan summary

Usage:
    from scanner.webhooks import WebhookNotifier, WebhookConfig

    config = WebhookConfig(
        enabled=True,
        slack_url="https://hooks.slack.com/services/...",
        teams_url="https://outlook.office.com/webhook/...",
        discord_url="https://discord.com/api/webhooks/...",
    )

    notifier = WebhookNotifier(config)
    notifier.notify_scan_complete(summary, scan_id="abc123")
"""

import logging
from dataclasses import dataclass, field
from typing import Optional

import requests

from scanner.reporting.models import ScanSummary

logger = logging.getLogger(__name__)


@dataclass
class WebhookConfig:
    """Webhook notification configuration."""
    enabled: bool = False
    slack_url: Optional[str] = None
    teams_url: Optional[str] = None
    discord_url: Optional[str] = None
    generic_urls: list[str] = field(default_factory=list)
    timeout: int = 15
    on_findings_only: bool = False


class WebhookNotifier:
    """
    Sends scan completion notifications to configured webhook endpoints.

    Automatically formats messages for each platform's expected format.
    Failures are logged but never raise — notifications are best-effort.
    """

    def __init__(self, config: WebhookConfig) -> None:
        self.config = config

    def notify_scan_complete(
        self,
        summary: ScanSummary,
        scan_id: str = "",
    ) -> None:
        """Send notifications to all configured webhooks."""
        if not self.config.enabled:
            return

        if self.config.on_findings_only and summary.total_findings == 0:
            logger.debug("No findings — skipping webhook notifications")
            return

        if self.config.slack_url:
            self._send_slack(summary, scan_id)

        if self.config.teams_url:
            self._send_teams(summary, scan_id)

        if self.config.discord_url:
            self._send_discord(summary, scan_id)

        for url in self.config.generic_urls:
            self._send_generic(url, summary, scan_id)

    # ----- Slack -----

    def _send_slack(self, summary: ScanSummary, scan_id: str) -> None:
        sev_emoji = {"Critical": ":red_circle:", "High": ":large_orange_circle:",
                     "Medium": ":large_yellow_circle:", "Low": ":large_blue_circle:"}

        findings_text = (
            f"{sev_emoji['Critical']} Critical: *{summary.critical_count}*  "
            f"{sev_emoji['High']} High: *{summary.high_count}*  "
            f"{sev_emoji['Medium']} Medium: *{summary.medium_count}*  "
            f"{sev_emoji['Low']} Low: *{summary.low_count}*"
        )

        status = ":white_check_mark: Clean" if summary.total_findings == 0 else f":warning: {summary.total_findings} finding(s)"

        payload = {
            "blocks": [
                {
                    "type": "header",
                    "text": {"type": "plain_text", "text": "W3BSP1D3R Scan Complete"},
                },
                {
                    "type": "section",
                    "fields": [
                        {"type": "mrkdwn", "text": f"*Target:*\n`{summary.target_url}`"},
                        {"type": "mrkdwn", "text": f"*Scan Type:*\n{summary.scan_type}"},
                        {"type": "mrkdwn", "text": f"*Status:*\n{status}"},
                        {"type": "mrkdwn", "text": f"*Scan ID:*\n`{scan_id}`"},
                    ],
                },
                {
                    "type": "section",
                    "text": {"type": "mrkdwn", "text": f"*Severity Breakdown:*\n{findings_text}"},
                },
                {
                    "type": "context",
                    "elements": [
                        {"type": "mrkdwn", "text": f"Pages: {summary.pages_crawled} | Forms: {summary.forms_found} | Params: {summary.params_tested}"},
                    ],
                },
            ],
        }

        self._post(self.config.slack_url, payload, "Slack")

    # ----- Microsoft Teams -----

    def _send_teams(self, summary: ScanSummary, scan_id: str) -> None:
        colour = "d63333" if summary.critical_count > 0 else (
            "ea580c" if summary.high_count > 0 else (
                "ca8a04" if summary.medium_count > 0 else "2563eb"
            )
        )
        if summary.total_findings == 0:
            colour = "2ea043"

        payload = {
            "@type": "MessageCard",
            "@context": "http://schema.org/extensions",
            "themeColor": colour,
            "summary": f"W3BSP1D3R Scan: {summary.target_url}",
            "sections": [
                {
                    "activityTitle": "W3BSP1D3R Scan Complete",
                    "activitySubtitle": summary.target_url,
                    "facts": [
                        {"name": "Scan Type", "value": summary.scan_type},
                        {"name": "Scan ID", "value": scan_id},
                        {"name": "Total Findings", "value": str(summary.total_findings)},
                        {"name": "Critical", "value": str(summary.critical_count)},
                        {"name": "High", "value": str(summary.high_count)},
                        {"name": "Medium", "value": str(summary.medium_count)},
                        {"name": "Low", "value": str(summary.low_count)},
                        {"name": "Pages Crawled", "value": str(summary.pages_crawled)},
                    ],
                    "markdown": True,
                },
            ],
        }

        self._post(self.config.teams_url, payload, "Teams")

    # ----- Discord -----

    def _send_discord(self, summary: ScanSummary, scan_id: str) -> None:
        colour = 0xDC2626 if summary.critical_count > 0 else (
            0xEA580C if summary.high_count > 0 else (
                0xCA8A04 if summary.medium_count > 0 else 0x2563EB
            )
        )
        if summary.total_findings == 0:
            colour = 0x2EA043

        embed = {
            "title": "W3BSP1D3R Scan Complete",
            "color": colour,
            "fields": [
                {"name": "Target", "value": f"`{summary.target_url}`", "inline": True},
                {"name": "Scan Type", "value": summary.scan_type, "inline": True},
                {"name": "Scan ID", "value": f"`{scan_id}`", "inline": True},
                {"name": "Critical", "value": str(summary.critical_count), "inline": True},
                {"name": "High", "value": str(summary.high_count), "inline": True},
                {"name": "Medium", "value": str(summary.medium_count), "inline": True},
                {"name": "Low", "value": str(summary.low_count), "inline": True},
                {"name": "Total", "value": f"**{summary.total_findings}**", "inline": True},
                {"name": "Pages", "value": str(summary.pages_crawled), "inline": True},
            ],
            "footer": {"text": "W3BSP1D3R by S1YOL"},
        }

        payload = {"embeds": [embed]}
        self._post(self.config.discord_url, payload, "Discord")

    # ----- Generic -----

    def _send_generic(self, url: str, summary: ScanSummary, scan_id: str) -> None:
        payload = {
            "scanner": "W3BSP1D3R",
            "event": "scan_complete",
            "scan_id": scan_id,
            "target_url": summary.target_url,
            "scan_type": summary.scan_type,
            "started_at": summary.started_at,
            "finished_at": summary.finished_at,
            "total_findings": summary.total_findings,
            "severity": {
                "critical": summary.critical_count,
                "high": summary.high_count,
                "medium": summary.medium_count,
                "low": summary.low_count,
            },
            "pages_crawled": summary.pages_crawled,
            "forms_found": summary.forms_found,
            "params_tested": summary.params_tested,
        }

        self._post(url, payload, "generic webhook")

    # ----- HTTP sender -----

    def _post(self, url: str, payload: dict, platform: str) -> None:
        """POST JSON to a webhook URL. Failures are logged, never raised."""
        try:
            resp = requests.post(
                url,
                json=payload,
                timeout=self.config.timeout,
                headers={"Content-Type": "application/json"},
            )
            if resp.status_code < 300:
                logger.info("Webhook sent to %s (HTTP %d)", platform, resp.status_code)
            else:
                logger.warning(
                    "Webhook %s returned HTTP %d: %s",
                    platform, resp.status_code, resp.text[:200],
                )
        except Exception as exc:
            logger.warning("Webhook %s failed: %s", platform, exc)
