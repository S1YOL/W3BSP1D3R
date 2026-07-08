from __future__ import annotations
"""
scanner/api.py
----------------
REST API for programmatic scan management.

Provides a Flask-based HTTP API for:
  - Starting scans asynchronously
  - Querying scan status and results
  - Retrieving historical scan data
  - Downloading reports

This enables integration with CI/CD platforms, orchestration tools,
and custom dashboards.

Usage:
    # Start the API server
    python -m scanner.api --port 8888

    # Or from main.py
    python main.py --api-server --api-port 8888

Endpoints:
    POST   /api/v1/scans              Start a new scan
    GET    /api/v1/scans              List recent scans
    GET    /api/v1/scans/<id>         Get scan status and results
    GET    /api/v1/scans/<id>/findings  Get findings for a scan
    DELETE /api/v1/scans/<id>         Cancel a running scan (not implemented)
    GET    /api/v1/targets            List scanned targets
    GET    /api/v1/health             Health check
"""

import functools
import hashlib
import hmac
import json
import logging
import os
import secrets
import threading
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

logger = logging.getLogger(__name__)

# In-memory scan state (keyed by scan_id)
_active_scans: dict[str, dict[str, Any]] = {}
_scan_lock = threading.Lock()


def create_api_app(db=None, api_keys: list[str] | None = None):
    """
    Create and configure the Flask API application.

    Args:
        db: Optional ScanDatabase instance for historical data.
        api_keys: List of valid API keys. If empty/None, auth is disabled.

    Returns:
        Flask app instance.

    Raises:
        ImportError if Flask is not installed.
    """
    try:
        from flask import Flask, jsonify, request as flask_request
    except ImportError:
        raise ImportError(
            "REST API requires Flask. Install with: pip install flask"
        )

    app = Flask("w3bsp1d3r_api")
    app.config["JSON_SORT_KEYS"] = False

    # ---- API key authentication middleware ----
    _valid_keys: set[str] = set()
    if api_keys:
        _valid_keys = set(api_keys)
    else:
        # Check environment variable
        env_key = os.environ.get("W3BSP1D3R_API_KEY")
        if env_key:
            _valid_keys = {env_key}

    def require_api_key(f):
        """Decorator to enforce API key authentication on endpoints."""
        @functools.wraps(f)
        def decorated(*args, **kwargs):
            if not _valid_keys:
                return f(*args, **kwargs)  # No keys configured = auth disabled

            auth_header = flask_request.headers.get("Authorization", "")
            api_key_header = flask_request.headers.get("X-API-Key", "")
            api_key_param = flask_request.args.get("api_key", "")

            # Accept key from: Authorization: Bearer <key>, X-API-Key header, or ?api_key= param
            provided_key = ""
            if auth_header.startswith("Bearer "):
                provided_key = auth_header[7:]
            elif api_key_header:
                provided_key = api_key_header
            elif api_key_param:
                provided_key = api_key_param

            if not provided_key:
                return jsonify({
                    "error": "Authentication required",
                    "hint": "Provide API key via Authorization: Bearer <key>, X-API-Key header, or ?api_key= parameter",
                }), 401

            if not any(hmac.compare_digest(provided_key, k) for k in _valid_keys):
                return jsonify({"error": "Invalid API key"}), 403

            return f(*args, **kwargs)
        return decorated

    # ---- Health check (no auth required) ----
    @app.route("/api/v1/health", methods=["GET"])
    def health():
        return jsonify({
            "status": "ok",
            "scanner": "W3BSP1D3R",
            "version": "3.0.0-beta",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })

    # ---- Start a new scan ----
    @app.route("/api/v1/scans", methods=["POST"])
    @require_api_key
    def start_scan():
        data = flask_request.get_json(silent=True) or {}

        url = data.get("url")
        if not url:
            return jsonify({"error": "url is required"}), 400

        if not url.startswith(("http://", "https://")):
            return jsonify({"error": "url must start with http:// or https://"}), 400

        scan_id = uuid.uuid4().hex[:12]
        scan_config = {
            "url": url,
            "scan_type": data.get("scan_type", "full"),
            "threads": data.get("threads", 4),
            "max_pages": data.get("max_pages", 50),
            "delay": data.get("delay", 0.5),
            "timeout": data.get("timeout", 10),
            "verify_ssl": data.get("verify_ssl", True),
            "login_user": data.get("login_user"),
            "login_pass": data.get("login_pass"),
            "auth_token": data.get("auth_token"),
            "vt_api_key": data.get("vt_api_key"),
            "nvd_api_key": data.get("nvd_api_key"),
            "fail_on": data.get("fail_on"),
        }

        scan_state = {
            "scan_id": scan_id,
            "status": "queued",
            "config": scan_config,
            "started_at": datetime.now(timezone.utc).isoformat(),
            "finished_at": None,
            "summary": None,
            "error": None,
        }

        with _scan_lock:
            _active_scans[scan_id] = scan_state

        # Run scan in background thread
        thread = threading.Thread(
            target=_run_scan_async,
            args=(scan_id, scan_config, db),
            daemon=True,
        )
        thread.start()

        return jsonify({
            "scan_id": scan_id,
            "status": "queued",
            "message": "Scan started",
        }), 202

    # ---- List scans ----
    @app.route("/api/v1/scans", methods=["GET"])
    @require_api_key
    def list_scans():
        limit = flask_request.args.get("limit", 20, type=int)

        # Combine active scans with DB history
        scans = []
        with _scan_lock:
            for scan in list(_active_scans.values())[:limit]:
                scans.append({
                    "scan_id": scan["scan_id"],
                    "status": scan["status"],
                    "config": {
                        "url": scan["config"]["url"],
                        "scan_type": scan["config"]["scan_type"],
                    },
                    "started_at": scan["started_at"],
                    "finished_at": scan["finished_at"],
                })

        if db and len(scans) < limit:
            history = db.get_scan_history(limit=limit - len(scans))
            for h in history:
                if h["scan_id"] not in _active_scans:
                    scans.append({
                        "scan_id": h["scan_id"],
                        "status": "completed",
                        "config": {
                            "url": h["target_url"],
                            "scan_type": h["scan_type"],
                        },
                        "started_at": h["started_at"],
                        "finished_at": h.get("finished_at"),
                    })

        return jsonify({"scans": scans[:limit]})

    # ---- Get scan details ----
    @app.route("/api/v1/scans/<scan_id>", methods=["GET"])
    @require_api_key
    def get_scan(scan_id):
        with _scan_lock:
            scan = _active_scans.get(scan_id)

        if scan:
            result = {
                "scan_id": scan["scan_id"],
                "status": scan["status"],
                "started_at": scan["started_at"],
                "finished_at": scan["finished_at"],
                "error": scan["error"],
            }
            if scan["summary"]:
                result["summary"] = {
                    "target_url": scan["summary"].target_url,
                    "pages_crawled": scan["summary"].pages_crawled,
                    "forms_found": scan["summary"].forms_found,
                    "params_tested": scan["summary"].params_tested,
                    "total_findings": scan["summary"].total_findings,
                    "critical": scan["summary"].critical_count,
                    "high": scan["summary"].high_count,
                    "medium": scan["summary"].medium_count,
                    "low": scan["summary"].low_count,
                }
                result["findings"] = [
                    f.to_dict() for f in scan["summary"].sorted_findings()
                ]
            return jsonify(result)

        # Try database
        if db:
            history = db.get_scan_history()
            for h in history:
                if h["scan_id"] == scan_id:
                    findings = db.get_findings_by_scan(scan_id)
                    return jsonify({
                        "scan_id": scan_id,
                        "status": "completed",
                        "started_at": h["started_at"],
                        "finished_at": h.get("finished_at"),
                        "summary": {
                            "target_url": h["target_url"],
                            "pages_crawled": h["pages_crawled"],
                            "total_findings": h["total_findings"],
                            "critical": h["critical_count"],
                            "high": h["high_count"],
                            "medium": h["medium_count"],
                            "low": h["low_count"],
                        },
                        "findings": findings,
                    })

        return jsonify({"error": "Scan not found"}), 404

    # ---- Get scan findings ----
    @app.route("/api/v1/scans/<scan_id>/findings", methods=["GET"])
    @require_api_key
    def get_findings(scan_id):
        severity = flask_request.args.get("severity")

        with _scan_lock:
            scan = _active_scans.get(scan_id)

        findings = []
        if scan and scan["summary"]:
            findings = [f.to_dict() for f in scan["summary"].sorted_findings()]
        elif db:
            findings = db.get_findings_by_scan(scan_id)

        if severity:
            findings = [f for f in findings if f.get("severity", "").lower() == severity.lower()]

        return jsonify({"findings": findings, "count": len(findings)})

    # ---- List targets ----
    @app.route("/api/v1/targets", methods=["GET"])
    @require_api_key
    def list_targets():
        targets = []
        if db:
            targets = db.get_unique_targets()
        return jsonify({"targets": targets})

    # ---- Database stats ----
    @app.route("/api/v1/stats", methods=["GET"])
    @require_api_key
    def get_stats():
        stats = {}
        if db:
            stats = db.get_stats()
        stats["active_scans"] = sum(
            1 for s in _active_scans.values()
            if s["status"] in ("queued", "running")
        )
        return jsonify(stats)

    return app


def _run_scan_async(scan_id: str, config: dict, db=None) -> None:
    """Run a scan in a background thread."""
    from scanner.core import WebVulnScanner

    with _scan_lock:
        _active_scans[scan_id]["status"] = "running"

    try:
        scanner = WebVulnScanner(
            url=config["url"],
            scan_type=config.get("scan_type", "full"),
            login_user=config.get("login_user"),
            login_pass=config.get("login_pass"),
            output=f".w3bsp1d3r/api_reports/{scan_id}",
            max_pages=config.get("max_pages", 50),
            delay=config.get("delay", 0.5),
            timeout=config.get("timeout", 10),
            verify_ssl=config.get("verify_ssl", True),
            threads=config.get("threads", 4),
            vt_api_key=config.get("vt_api_key"),
            nvd_api_key=config.get("nvd_api_key"),
            auth_token=config.get("auth_token"),
            fail_on=config.get("fail_on"),
        )

        summary = scanner.scan()

        with _scan_lock:
            _active_scans[scan_id]["status"] = "completed"
            _active_scans[scan_id]["summary"] = summary
            _active_scans[scan_id]["finished_at"] = datetime.now(timezone.utc).isoformat()

        # Persist to database
        if db:
            db.save_scan(scan_id, summary, config=config)

    except Exception as exc:
        logger.error("API scan %s failed: %s", scan_id, exc)
        with _scan_lock:
            _active_scans[scan_id]["status"] = "failed"
            _active_scans[scan_id]["error"] = str(exc)
            _active_scans[scan_id]["finished_at"] = datetime.now(timezone.utc).isoformat()


def run_api_server(
    host: str = "127.0.0.1",
    port: int = 8888,
    db=None,
    api_keys: list[str] | None = None,
) -> None:
    """Start the API server."""
    app = create_api_app(db=db, api_keys=api_keys)
    auth_status = "enabled" if (api_keys or os.environ.get("W3BSP1D3R_API_KEY")) else "DISABLED (set W3BSP1D3R_API_KEY)"
    logger.info("Starting W3BSP1D3R API on %s:%d (auth: %s)", host, port, auth_status)
    print(f"  W3BSP1D3R API server on http://{host}:{port}  (auth: {auth_status})")
    app.run(host=host, port=port, debug=False, threaded=True)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="W3BSP1D3R REST API Server")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8888)
    parser.add_argument("--db", default=".w3bsp1d3r/scans.db")
    args = parser.parse_args()

    from scanner.db import ScanDatabase
    database = ScanDatabase(path=args.db)
    run_api_server(host=args.host, port=args.port, db=database)
