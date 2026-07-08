from __future__ import annotations
"""
scanner/audit.py
------------------
Enterprise audit trail for W3BSP1D3R.

Records who scanned what, when, and with what configuration.
Produces a structured, append-only audit log suitable for compliance
and incident review.

Each audit entry includes:
  - Timestamp (UTC ISO-8601)
  - Event type (scan_start, scan_complete, auth_attempt, finding, config_change)
  - Scan ID
  - Actor (system user or configured identity)
  - Target URL
  - Event-specific data

Usage:
    from scanner.audit import AuditLogger

    audit = AuditLogger(log_file=".w3bsp1d3r/audit.log")
    audit.log_scan_start(scan_id="abc", target="http://target.com", config={...})
    audit.log_finding(scan_id="abc", finding={...})
    audit.log_scan_complete(scan_id="abc", summary={...})
"""

import getpass
import json
import logging
import os
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger(__name__)


class AuditLogger:
    """
    Append-only audit logger for compliance and traceability.

    Writes one JSON object per line (JSONL format) for easy ingestion
    by log aggregation systems.
    """

    def __init__(
        self,
        log_file: str = ".w3bsp1d3r/audit.log",
        enabled: bool = True,
        actor: Optional[str] = None,
    ) -> None:
        self.enabled = enabled
        self.log_file = Path(log_file)
        self.actor = actor or _get_actor()
        self._lock = threading.Lock()

        if enabled:
            self.log_file.parent.mkdir(parents=True, exist_ok=True)

    def _write_entry(self, entry: dict[str, Any]) -> None:
        """Append a single audit entry to the log file."""
        if not self.enabled:
            return

        entry["timestamp"] = datetime.now(timezone.utc).isoformat()
        entry["actor"] = self.actor

        with self._lock:
            try:
                with self.log_file.open("a", encoding="utf-8") as fh:
                    fh.write(json.dumps(entry, default=str) + "\n")
            except OSError as exc:
                logger.warning("Audit log write failed: %s", exc)

    def log_scan_start(
        self,
        scan_id: str,
        target: str,
        scan_type: str,
        config: dict[str, Any],
    ) -> None:
        """Record the start of a scan."""
        # Redact sensitive fields from config
        safe_config = _redact_secrets(config)
        self._write_entry({
            "event": "scan_start",
            "scan_id": scan_id,
            "target": target,
            "scan_type": scan_type,
            "config": safe_config,
        })

    def log_scan_complete(
        self,
        scan_id: str,
        target: str,
        duration_seconds: float,
        findings_count: int,
        severity_breakdown: dict[str, int],
    ) -> None:
        """Record the completion of a scan."""
        self._write_entry({
            "event": "scan_complete",
            "scan_id": scan_id,
            "target": target,
            "duration_seconds": round(duration_seconds, 2),
            "findings_count": findings_count,
            "severity_breakdown": severity_breakdown,
        })

    def log_auth_attempt(
        self,
        scan_id: str,
        target: str,
        auth_type: str,
        success: bool,
        username: Optional[str] = None,
    ) -> None:
        """Record an authentication attempt."""
        self._write_entry({
            "event": "auth_attempt",
            "scan_id": scan_id,
            "target": target,
            "auth_type": auth_type,
            "success": success,
            "username": username,
        })

    def log_finding(
        self,
        scan_id: str,
        vuln_type: str,
        severity: str,
        url: str,
        parameter: str,
        fingerprint: str,
    ) -> None:
        """Record a vulnerability finding."""
        self._write_entry({
            "event": "finding",
            "scan_id": scan_id,
            "vuln_type": vuln_type,
            "severity": severity,
            "url": url,
            "parameter": parameter,
            "fingerprint": fingerprint,
        })

    def log_config_loaded(
        self,
        scan_id: str,
        config_source: str,
        profile: Optional[str] = None,
    ) -> None:
        """Record configuration loading."""
        self._write_entry({
            "event": "config_loaded",
            "scan_id": scan_id,
            "source": config_source,
            "profile": profile,
        })

    def log_policy_violation(
        self,
        scan_id: str,
        policy: str,
        original_value: Any,
        enforced_value: Any,
    ) -> None:
        """Record when a policy enforcement changes a configuration value."""
        self._write_entry({
            "event": "policy_violation",
            "scan_id": scan_id,
            "policy": policy,
            "original_value": original_value,
            "enforced_value": enforced_value,
        })

    def log_error(
        self,
        scan_id: str,
        error_type: str,
        message: str,
        context: Optional[dict] = None,
    ) -> None:
        """Record an error event."""
        self._write_entry({
            "event": "error",
            "scan_id": scan_id,
            "error_type": error_type,
            "message": message,
            "context": context or {},
        })

    def get_entries(
        self,
        scan_id: Optional[str] = None,
        event_type: Optional[str] = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        """Read audit entries, optionally filtered by scan_id or event type."""
        if not self.log_file.exists():
            return []

        entries = []
        try:
            with self.log_file.open("r", encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        entry = json.loads(line)
                        if scan_id and entry.get("scan_id") != scan_id:
                            continue
                        if event_type and entry.get("event") != event_type:
                            continue
                        entries.append(entry)
                    except json.JSONDecodeError:
                        continue
        except OSError:
            return []

        return entries[-limit:]


def _get_actor() -> str:
    """Get the current system user identity."""
    try:
        return f"{getpass.getuser()}@{os.uname().nodename}"
    except (AttributeError, OSError):
        try:
            return getpass.getuser()
        except Exception:
            return "unknown"


def _redact_secrets(config: dict[str, Any]) -> dict[str, Any]:
    """Redact sensitive values from config for audit logging."""
    sensitive_keys = {
        "password", "login_pass", "auth_token", "token",
        "vt_api_key", "nvd_api_key", "api_key",
        "client_secret", "oauth2_client_secret",
    }
    redacted = {}
    for key, value in config.items():
        if isinstance(value, dict):
            redacted[key] = _redact_secrets(value)
        elif any(s in key.lower() for s in sensitive_keys):
            redacted[key] = "***REDACTED***" if value else None
        else:
            redacted[key] = value
    return redacted
