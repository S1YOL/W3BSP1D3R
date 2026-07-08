from __future__ import annotations
"""
scanner/utils/logging_config.py
---------------------------------
Structured logging configuration for enterprise deployments.

Supports two output modes:
  - "text": Human-readable format (default, same as before)
  - "json": Structured JSON lines for SIEM/ELK/Datadog/Splunk ingestion

JSON mode adds fields: timestamp, level, logger, message, request_id,
scan_id, module, and any extra context passed via the `extra` dict.

Usage:
    from scanner.utils.logging_config import configure_logging

    configure_logging(level="DEBUG", fmt="json", log_file="scan.log")
"""

import json
import logging
import sys
import threading
import uuid
from datetime import datetime, timezone
from typing import Optional


# Thread-local storage for request correlation
_context = threading.local()


def set_scan_id(scan_id: str) -> None:
    """Set the scan ID for the current thread's log context."""
    _context.scan_id = scan_id


def get_scan_id() -> str:
    """Get the current scan ID, or 'none' if not set."""
    return getattr(_context, "scan_id", "none")


def new_request_id() -> str:
    """Generate a short unique request ID for correlating log entries."""
    return uuid.uuid4().hex[:12]


def set_request_id(request_id: str) -> None:
    """Set the request ID for the current thread."""
    _context.request_id = request_id


def get_request_id() -> str:
    """Get the current request ID."""
    return getattr(_context, "request_id", "none")


# ---------------------------------------------------------------------------
# JSON formatter
# ---------------------------------------------------------------------------

class JSONFormatter(logging.Formatter):
    """
    Formats log records as single-line JSON objects.

    Output fields:
      - timestamp: ISO-8601 UTC timestamp
      - level: Log level name
      - logger: Logger name (module path)
      - message: The formatted log message
      - scan_id: Scan correlation ID
      - request_id: Per-request correlation ID
      - module: Python module name
      - func: Function name
      - line: Line number
      - extra: Any additional fields from record.__dict__
    """

    # Standard LogRecord attributes to exclude from extra fields
    _SKIP_FIELDS = {
        "name", "msg", "args", "created", "relativeCreated", "exc_info",
        "exc_text", "stack_info", "lineno", "funcName", "pathname",
        "filename", "module", "thread", "threadName", "processName",
        "process", "levelname", "levelno", "msecs", "message",
        "taskName",
    }

    def format(self, record: logging.LogRecord) -> str:
        record.getMessage()  # Populate record.message

        entry = {
            "timestamp": datetime.fromtimestamp(
                record.created, tz=timezone.utc
            ).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "scan_id": get_scan_id(),
            "request_id": get_request_id(),
            "module": record.module,
            "func": record.funcName,
            "line": record.lineno,
        }

        # Collect extra fields added via logger.info("msg", extra={...})
        extra = {}
        for key, value in record.__dict__.items():
            if key not in self._SKIP_FIELDS and not key.startswith("_"):
                try:
                    json.dumps(value)  # Only include JSON-serializable values
                    extra[key] = value
                except (TypeError, ValueError):
                    extra[key] = str(value)
        if extra:
            entry["extra"] = extra

        # Include exception info if present
        if record.exc_info and record.exc_info[1]:
            entry["exception"] = {
                "type": type(record.exc_info[1]).__name__,
                "message": str(record.exc_info[1]),
            }

        return json.dumps(entry, ensure_ascii=False, default=str)


# ---------------------------------------------------------------------------
# Text formatter (enhanced version of original)
# ---------------------------------------------------------------------------

class EnhancedTextFormatter(logging.Formatter):
    """Enhanced text formatter with optional request/scan IDs."""

    def __init__(self, include_ids: bool = False):
        if include_ids:
            fmt = (
                "%(asctime)s [%(levelname)-8s] %(name)s "
                "[scan:%(scan_id)s req:%(request_id)s] %(message)s"
            )
        else:
            fmt = "%(asctime)s [%(levelname)-8s] %(name)s: %(message)s"
        super().__init__(fmt=fmt, datefmt="%H:%M:%S")

    def format(self, record: logging.LogRecord) -> str:
        record.scan_id = get_scan_id()
        record.request_id = get_request_id()
        return super().format(record)


# ---------------------------------------------------------------------------
# Configuration entry point
# ---------------------------------------------------------------------------

def configure_logging(
    level: str = "WARNING",
    fmt: str = "text",
    log_file: Optional[str] = None,
    include_ids: bool = True,
    scan_id: Optional[str] = None,
) -> None:
    """
    Configure the logging system for W3BSP1D3R.

    Args:
        level       : Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        fmt         : Output format ("text" or "json")
        log_file    : Optional file path to write logs to (in addition to stderr)
        include_ids : Whether to include scan/request IDs in text mode
        scan_id     : Scan correlation ID (auto-generated if not provided)
    """
    # Set the scan ID for this session
    if scan_id:
        set_scan_id(scan_id)
    else:
        set_scan_id(uuid.uuid4().hex[:8])

    # Create formatter
    if fmt == "json":
        formatter = JSONFormatter()
    else:
        formatter = EnhancedTextFormatter(include_ids=include_ids)

    # Configure root logger
    root = logging.getLogger()
    root.setLevel(getattr(logging, level.upper(), logging.WARNING))

    # Clear existing handlers
    root.handlers.clear()

    # Stderr handler
    stderr_handler = logging.StreamHandler(sys.stderr)
    stderr_handler.setFormatter(formatter)
    root.addHandler(stderr_handler)

    # Optional file handler
    if log_file:
        from pathlib import Path
        Path(log_file).parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(log_file, encoding="utf-8")
        file_handler.setFormatter(formatter)
        root.addHandler(file_handler)

    logging.getLogger(__name__).debug(
        "Logging configured: level=%s, format=%s, file=%s",
        level, fmt, log_file,
    )
