from __future__ import annotations
"""
scanner/checkpoint.py
-----------------------
Scan checkpoint and resume system.

Saves scan state periodically so that long-running scans can be resumed
after crashes, network interruptions, or user-initiated pauses.

State is stored as JSON files in a configurable checkpoint directory.

Usage:
    from scanner.checkpoint import CheckpointManager

    cp = CheckpointManager(scan_id="abc123", directory=".w3bsp1d3r/checkpoints")

    # Save state during scan
    cp.save_crawl_state(visited_urls, queue, pages)
    cp.save_tester_progress(tester_name, findings)

    # Resume from checkpoint
    if cp.has_checkpoint():
        state = cp.load()
"""

import json
import logging
import os
import time
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger(__name__)


class CheckpointManager:
    """
    Manages scan checkpoints for crash recovery and resume.

    Checkpoint data is stored as JSON files with atomic writes
    (write to temp, then rename) to prevent corruption.
    """

    def __init__(
        self,
        scan_id: str,
        directory: str = ".w3bsp1d3r/checkpoints",
        enabled: bool = True,
        save_interval: float = 30.0,
    ) -> None:
        self.scan_id = scan_id
        self.directory = Path(directory)
        self.enabled = enabled
        self.save_interval = save_interval
        self._last_save = 0.0

        if enabled:
            self.directory.mkdir(parents=True, exist_ok=True)

    @property
    def _checkpoint_path(self) -> Path:
        return self.directory / f"{self.scan_id}.json"

    @property
    def _temp_path(self) -> Path:
        return self.directory / f"{self.scan_id}.json.tmp"

    def has_checkpoint(self) -> bool:
        """Check if a checkpoint exists for this scan."""
        return self._checkpoint_path.exists()

    def save(self, state: dict[str, Any]) -> None:
        """
        Save scan state to a checkpoint file.

        Uses atomic write (temp + rename) to prevent corruption.
        Respects save_interval to avoid excessive I/O.
        """
        if not self.enabled:
            return

        now = time.monotonic()
        if now - self._last_save < self.save_interval:
            return

        state["_checkpoint_meta"] = {
            "scan_id": self.scan_id,
            "saved_at": datetime.now(timezone.utc).isoformat(),
            "version": "1.0",
        }

        try:
            with self._temp_path.open("w", encoding="utf-8") as fh:
                json.dump(state, fh, indent=2, default=str)
            self._temp_path.replace(self._checkpoint_path)
            self._last_save = now
            logger.debug("Checkpoint saved: %s", self._checkpoint_path)
        except OSError as exc:
            logger.warning("Failed to save checkpoint: %s", exc)

    def save_crawl_state(
        self,
        visited_urls: list[str],
        queue_urls: list[str],
        pages_data: list[dict],
    ) -> None:
        """Save the crawler state."""
        self.save({
            "phase": "crawl",
            "visited_urls": visited_urls,
            "queue_urls": queue_urls,
            "pages_count": len(pages_data),
        })

    def save_tester_progress(
        self,
        completed_testers: list[str],
        findings: list[dict],
        params_tested: int,
    ) -> None:
        """Save tester execution progress."""
        self.save({
            "phase": "testing",
            "completed_testers": completed_testers,
            "findings": findings,
            "params_tested": params_tested,
        })

    def load(self) -> Optional[dict[str, Any]]:
        """
        Load the checkpoint state.

        Returns None if no checkpoint exists or the file is corrupted.
        """
        if not self.has_checkpoint():
            return None

        try:
            with self._checkpoint_path.open("r", encoding="utf-8") as fh:
                state = json.load(fh)
            logger.info(
                "Checkpoint loaded: %s (saved at %s)",
                self.scan_id,
                state.get("_checkpoint_meta", {}).get("saved_at", "unknown"),
            )
            return state
        except (json.JSONDecodeError, OSError) as exc:
            logger.warning("Failed to load checkpoint: %s", exc)
            return None

    def clear(self) -> None:
        """Remove the checkpoint file after a successful scan completion."""
        if self._checkpoint_path.exists():
            self._checkpoint_path.unlink()
            logger.debug("Checkpoint cleared: %s", self.scan_id)
        if self._temp_path.exists():
            self._temp_path.unlink()

    def list_checkpoints(self) -> list[dict[str, Any]]:
        """List all available checkpoints in the directory."""
        checkpoints = []
        if not self.directory.exists():
            return checkpoints

        for path in self.directory.glob("*.json"):
            if path.name.endswith(".tmp"):
                continue
            try:
                with path.open("r", encoding="utf-8") as fh:
                    state = json.load(fh)
                meta = state.get("_checkpoint_meta", {})
                checkpoints.append({
                    "scan_id": meta.get("scan_id", path.stem),
                    "saved_at": meta.get("saved_at", "unknown"),
                    "phase": state.get("phase", "unknown"),
                    "path": str(path),
                })
            except (json.JSONDecodeError, OSError):
                continue

        return sorted(checkpoints, key=lambda c: c["saved_at"], reverse=True)
