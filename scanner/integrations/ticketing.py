from __future__ import annotations
"""
scanner/integrations/ticketing.py
------------------------------------
Jira and ServiceNow integration for automatic ticket creation.

Creates tickets/issues from scan findings so vulnerabilities flow
directly into the enterprise workflow.

Usage:
    from scanner.integrations.ticketing import JiraClient, ServiceNowClient

    # Jira
    jira = JiraClient(url="https://company.atlassian.net", email="user@co.com",
                      api_token="token", project_key="SEC")
    jira.create_tickets(summary)

    # ServiceNow
    snow = ServiceNowClient(instance="company", username="admin", password="pass")
    snow.create_incidents(summary)
"""

import json
import logging
from dataclasses import dataclass, field
from typing import Any, Optional

import requests

from scanner.reporting.models import Finding, ScanSummary, Severity, get_owasp_category

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

@dataclass
class JiraConfig:
    """Jira integration configuration."""
    enabled: bool = False
    url: str = ""               # https://company.atlassian.net
    email: str = ""             # user@company.com
    api_token: str = ""         # Jira API token
    project_key: str = ""       # e.g. "SEC"
    issue_type: str = "Bug"     # Bug, Task, Story, Security
    min_severity: str = "Medium"  # Only create tickets for this severity and above
    labels: list[str] = field(default_factory=lambda: ["w3bsp1d3r", "security"])
    assignee: Optional[str] = None


@dataclass
class ServiceNowConfig:
    """ServiceNow integration configuration."""
    enabled: bool = False
    instance: str = ""          # company (for company.service-now.com)
    username: str = ""
    password: str = ""
    assignment_group: str = ""
    category: str = "Security"
    min_severity: str = "Medium"


# ---------------------------------------------------------------------------
# Severity gating
# ---------------------------------------------------------------------------

_SEV_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}


def _meets_threshold(finding_severity: str, min_severity: str) -> bool:
    """Check if a finding severity meets the minimum threshold."""
    return _SEV_ORDER.get(finding_severity, 99) <= _SEV_ORDER.get(min_severity, 99)


# ---------------------------------------------------------------------------
# Jira Client
# ---------------------------------------------------------------------------

class JiraClient:
    """Creates Jira issues from scan findings."""

    def __init__(self, config: JiraConfig) -> None:
        self.config = config
        self._session = requests.Session()
        self._session.auth = (config.email, config.api_token)
        self._session.headers["Content-Type"] = "application/json"
        self._session.headers["Accept"] = "application/json"

    def create_tickets(self, summary: ScanSummary, scan_id: str = "") -> list[str]:
        """
        Create Jira issues for findings that meet the severity threshold.
        Returns list of created issue keys (e.g. ["SEC-123", "SEC-124"]).
        """
        if not self.config.enabled:
            return []

        created = []
        for finding in summary.sorted_findings():
            if not _meets_threshold(finding.severity, self.config.min_severity):
                continue

            issue_key = self._create_issue(finding, scan_id)
            if issue_key:
                created.append(issue_key)

        logger.info("Created %d Jira issue(s)", len(created))
        return created

    def _create_issue(self, finding: Finding, scan_id: str) -> Optional[str]:
        """Create a single Jira issue from a finding."""
        owasp = get_owasp_category(finding.vuln_type)
        owasp_label = f"[{owasp['id']}] " if owasp else ""

        description = (
            f"h2. {finding.vuln_type}\n\n"
            f"*Severity:* {finding.severity}\n"
            f"*URL:* {finding.url}\n"
            f"*Parameter:* {finding.parameter}\n"
            f"*Method:* {finding.method}\n"
            f"*Scan ID:* {scan_id}\n"
            f"*Fingerprint:* {finding.fingerprint}\n\n"
            f"h3. Proof-of-Concept Payload\n{{code}}\n{finding.payload}\n{{code}}\n\n"
            f"h3. Evidence\n{finding.evidence[:500]}\n\n"
            f"h3. Remediation\n{finding.remediation}\n\n"
        )
        if owasp:
            description += f"h3. OWASP Top 10\n{owasp['id']} — {owasp['name']}\n"

        priority_map = {"Critical": "Highest", "High": "High", "Medium": "Medium", "Low": "Low"}

        payload = {
            "fields": {
                "project": {"key": self.config.project_key},
                "issuetype": {"name": self.config.issue_type},
                "summary": f"{owasp_label}{finding.vuln_type} — {finding.parameter} @ {finding.url[:80]}",
                "description": description,
                "priority": {"name": priority_map.get(finding.severity, "Medium")},
                "labels": self.config.labels,
            }
        }

        if self.config.assignee:
            payload["fields"]["assignee"] = {"accountId": self.config.assignee}

        try:
            resp = self._session.post(
                f"{self.config.url}/rest/api/2/issue",
                data=json.dumps(payload),
                timeout=30,
            )
            if resp.status_code == 201:
                key = resp.json().get("key", "")
                logger.info("Created Jira issue: %s", key)
                return key
            else:
                logger.warning("Jira issue creation failed (%d): %s", resp.status_code, resp.text[:200])
                return None
        except Exception as exc:
            logger.warning("Jira API error: %s", exc)
            return None


# ---------------------------------------------------------------------------
# ServiceNow Client
# ---------------------------------------------------------------------------

class ServiceNowClient:
    """Creates ServiceNow incidents from scan findings."""

    def __init__(self, config: ServiceNowConfig) -> None:
        self.config = config
        self._base_url = f"https://{config.instance}.service-now.com"
        self._session = requests.Session()
        self._session.auth = (config.username, config.password)
        self._session.headers["Content-Type"] = "application/json"
        self._session.headers["Accept"] = "application/json"

    def create_incidents(self, summary: ScanSummary, scan_id: str = "") -> list[str]:
        """
        Create ServiceNow incidents for findings that meet the threshold.
        Returns list of created incident numbers.
        """
        if not self.config.enabled:
            return []

        created = []
        for finding in summary.sorted_findings():
            if not _meets_threshold(finding.severity, self.config.min_severity):
                continue

            number = self._create_incident(finding, scan_id)
            if number:
                created.append(number)

        logger.info("Created %d ServiceNow incident(s)", len(created))
        return created

    def _create_incident(self, finding: Finding, scan_id: str) -> Optional[str]:
        """Create a single ServiceNow incident."""
        urgency_map = {"Critical": "1", "High": "2", "Medium": "2", "Low": "3"}
        impact_map = {"Critical": "1", "High": "2", "Medium": "2", "Low": "3"}

        owasp = get_owasp_category(finding.vuln_type)
        owasp_info = f"\n\nOWASP: {owasp['id']} — {owasp['name']}" if owasp else ""

        payload = {
            "short_description": f"[W3BSP1D3R] {finding.vuln_type} — {finding.url[:80]}",
            "description": (
                f"Vulnerability: {finding.vuln_type}\n"
                f"Severity: {finding.severity}\n"
                f"URL: {finding.url}\n"
                f"Parameter: {finding.parameter}\n"
                f"Method: {finding.method}\n"
                f"Scan ID: {scan_id}\n"
                f"Fingerprint: {finding.fingerprint}\n\n"
                f"Payload: {finding.payload}\n\n"
                f"Evidence: {finding.evidence[:500]}\n\n"
                f"Remediation: {finding.remediation}"
                f"{owasp_info}"
            ),
            "urgency": urgency_map.get(finding.severity, "2"),
            "impact": impact_map.get(finding.severity, "2"),
            "category": self.config.category,
        }

        if self.config.assignment_group:
            payload["assignment_group"] = self.config.assignment_group

        try:
            resp = self._session.post(
                f"{self._base_url}/api/now/table/incident",
                data=json.dumps(payload),
                timeout=30,
            )
            if resp.status_code == 201:
                number = resp.json().get("result", {}).get("number", "")
                logger.info("Created ServiceNow incident: %s", number)
                return number
            else:
                logger.warning("ServiceNow failed (%d): %s", resp.status_code, resp.text[:200])
                return None
        except Exception as exc:
            logger.warning("ServiceNow API error: %s", exc)
            return None
