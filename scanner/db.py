from __future__ import annotations
"""
scanner/db.py
---------------
SQLite-based persistence for historical scan data.

Stores scan summaries, individual findings, and request metrics
so that enterprise teams can:
  - Track vulnerability trends over time
  - Compare scans across releases
  - Generate compliance reports
  - Query historical findings

Schema is auto-created on first use. Migrations are handled
by checking schema version.

Usage:
    from scanner.db import ScanDatabase

    db = ScanDatabase(path=".w3bsp1d3r/scans.db")
    db.save_scan(summary)
    history = db.get_scan_history(target_url="http://example.com")
    trends = db.get_severity_trends(target_url="http://example.com")
"""

import json
import logging
import sqlite3
import threading
from pathlib import Path
from typing import Any, Optional

from scanner.reporting.models import ScanSummary

logger = logging.getLogger(__name__)

SCHEMA_VERSION = 1

_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS schema_version (
    version INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS scans (
    scan_id       TEXT PRIMARY KEY,
    target_url    TEXT NOT NULL,
    scan_type     TEXT NOT NULL,
    started_at    TEXT NOT NULL,
    finished_at   TEXT,
    pages_crawled INTEGER DEFAULT 0,
    forms_found   INTEGER DEFAULT 0,
    params_tested INTEGER DEFAULT 0,
    total_findings INTEGER DEFAULT 0,
    critical_count INTEGER DEFAULT 0,
    high_count    INTEGER DEFAULT 0,
    medium_count  INTEGER DEFAULT 0,
    low_count     INTEGER DEFAULT 0,
    config_json   TEXT,
    metrics_json  TEXT,
    created_at    TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS findings (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id      TEXT NOT NULL,
    fingerprint  TEXT NOT NULL,
    vuln_type    TEXT NOT NULL,
    severity     TEXT NOT NULL,
    url          TEXT NOT NULL,
    parameter    TEXT,
    method       TEXT,
    payload      TEXT,
    evidence     TEXT,
    remediation  TEXT,
    timestamp    TEXT,
    extra_json   TEXT,
    FOREIGN KEY (scan_id) REFERENCES scans(scan_id)
);

CREATE INDEX IF NOT EXISTS idx_findings_scan_id ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_fingerprint ON findings(fingerprint);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_scans_target ON scans(target_url);
CREATE INDEX IF NOT EXISTS idx_scans_started ON scans(started_at);
"""


class ScanDatabase:
    """
    SQLite database for historical scan persistence.

    Thread-safe via connection-per-thread pattern.
    """

    def __init__(self, path: str = ".w3bsp1d3r/scans.db", enabled: bool = True) -> None:
        self.path = Path(path)
        self.enabled = enabled
        self._local = threading.local()

        if enabled:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self._init_schema()

    def _get_conn(self) -> sqlite3.Connection:
        """Get a thread-local database connection."""
        if not hasattr(self._local, "conn") or self._local.conn is None:
            self._local.conn = sqlite3.connect(
                str(self.path),
                timeout=30,
                check_same_thread=False,
            )
            self._local.conn.row_factory = sqlite3.Row
            self._local.conn.execute("PRAGMA journal_mode=WAL")
            self._local.conn.execute("PRAGMA foreign_keys=ON")
        return self._local.conn

    def _init_schema(self) -> None:
        """Create tables if they don't exist."""
        conn = self._get_conn()
        conn.executescript(_SCHEMA_SQL)

        # Check/set schema version
        cursor = conn.execute("SELECT version FROM schema_version LIMIT 1")
        row = cursor.fetchone()
        if row is None:
            conn.execute(
                "INSERT INTO schema_version (version) VALUES (?)",
                (SCHEMA_VERSION,),
            )
        conn.commit()

    def save_scan(
        self,
        scan_id: str,
        summary: ScanSummary,
        config: dict[str, Any] | None = None,
        metrics: dict[str, Any] | None = None,
    ) -> None:
        """Save a completed scan and all its findings to the database."""
        if not self.enabled:
            return

        conn = self._get_conn()
        try:
            conn.execute(
                """INSERT OR REPLACE INTO scans
                   (scan_id, target_url, scan_type, started_at, finished_at,
                    pages_crawled, forms_found, params_tested, total_findings,
                    critical_count, high_count, medium_count, low_count,
                    config_json, metrics_json)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    scan_id,
                    summary.target_url,
                    summary.scan_type,
                    summary.started_at,
                    summary.finished_at,
                    summary.pages_crawled,
                    summary.forms_found,
                    summary.params_tested,
                    summary.total_findings,
                    summary.critical_count,
                    summary.high_count,
                    summary.medium_count,
                    summary.low_count,
                    json.dumps(config, default=str) if config else None,
                    json.dumps(metrics, default=str) if metrics else None,
                ),
            )

            # Save individual findings
            for finding in summary.findings:
                conn.execute(
                    """INSERT INTO findings
                       (scan_id, fingerprint, vuln_type, severity, url,
                        parameter, method, payload, evidence, remediation,
                        timestamp, extra_json)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        scan_id,
                        finding.fingerprint,
                        finding.vuln_type,
                        finding.severity,
                        finding.url,
                        finding.parameter,
                        finding.method,
                        finding.payload,
                        finding.evidence,
                        finding.remediation,
                        finding.timestamp,
                        json.dumps(finding.extra, default=str) if finding.extra else None,
                    ),
                )

            conn.commit()
            logger.info(
                "Scan %s saved to database (%d findings)",
                scan_id, summary.total_findings,
            )
        except sqlite3.Error as exc:
            logger.error("Database write failed: %s", exc)
            conn.rollback()

    def get_scan_history(
        self,
        target_url: Optional[str] = None,
        limit: int = 50,
    ) -> list[dict[str, Any]]:
        """Get historical scan records, optionally filtered by target."""
        if not self.enabled:
            return []

        conn = self._get_conn()

        if target_url:
            cursor = conn.execute(
                """SELECT * FROM scans WHERE target_url = ?
                   ORDER BY started_at DESC LIMIT ?""",
                (target_url, limit),
            )
        else:
            cursor = conn.execute(
                "SELECT * FROM scans ORDER BY started_at DESC LIMIT ?",
                (limit,),
            )

        return [dict(row) for row in cursor.fetchall()]

    def get_findings_by_scan(self, scan_id: str) -> list[dict[str, Any]]:
        """Get all findings for a specific scan."""
        if not self.enabled:
            return []

        conn = self._get_conn()
        cursor = conn.execute(
            "SELECT * FROM findings WHERE scan_id = ? ORDER BY severity",
            (scan_id,),
        )
        return [dict(row) for row in cursor.fetchall()]

    def get_severity_trends(
        self,
        target_url: str,
        limit: int = 20,
    ) -> list[dict[str, Any]]:
        """Get severity count trends over time for a target."""
        if not self.enabled:
            return []

        conn = self._get_conn()
        cursor = conn.execute(
            """SELECT scan_id, started_at, total_findings,
                      critical_count, high_count, medium_count, low_count
               FROM scans WHERE target_url = ?
               ORDER BY started_at DESC LIMIT ?""",
            (target_url, limit),
        )
        return [dict(row) for row in cursor.fetchall()]

    def get_finding_history(
        self,
        fingerprint: str,
        limit: int = 20,
    ) -> list[dict[str, Any]]:
        """Track a specific finding across scans by its fingerprint."""
        if not self.enabled:
            return []

        conn = self._get_conn()
        cursor = conn.execute(
            """SELECT f.*, s.started_at as scan_date, s.target_url
               FROM findings f
               JOIN scans s ON f.scan_id = s.scan_id
               WHERE f.fingerprint = ?
               ORDER BY s.started_at DESC LIMIT ?""",
            (fingerprint, limit),
        )
        return [dict(row) for row in cursor.fetchall()]

    def get_latest_scan_id(self, target_url: str) -> Optional[str]:
        """Get the most recent scan ID for a target URL."""
        if not self.enabled:
            return None

        conn = self._get_conn()
        cursor = conn.execute(
            """SELECT scan_id FROM scans WHERE target_url = ?
               ORDER BY started_at DESC LIMIT 1""",
            (target_url,),
        )
        row = cursor.fetchone()
        return row["scan_id"] if row else None

    def get_unique_targets(self) -> list[str]:
        """Get all unique target URLs that have been scanned."""
        if not self.enabled:
            return []

        conn = self._get_conn()
        cursor = conn.execute(
            "SELECT DISTINCT target_url FROM scans ORDER BY target_url"
        )
        return [row["target_url"] for row in cursor.fetchall()]

    def get_stats(self) -> dict[str, Any]:
        """Get overall database statistics."""
        if not self.enabled:
            return {}

        conn = self._get_conn()
        scan_count = conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
        finding_count = conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
        target_count = conn.execute(
            "SELECT COUNT(DISTINCT target_url) FROM scans"
        ).fetchone()[0]

        return {
            "total_scans": scan_count,
            "total_findings": finding_count,
            "unique_targets": target_count,
        }

    def close(self) -> None:
        """Close the database connection."""
        if hasattr(self._local, "conn") and self._local.conn:
            self._local.conn.close()
            self._local.conn = None
