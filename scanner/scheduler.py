from __future__ import annotations
"""
scanner/scheduler.py
-----------------------
Cron-based scan scheduler for recurring vulnerability scans.

Runs scans at configurable intervals (hourly, daily, weekly, cron expression).
Each scheduled scan uses a ScanConfig and produces reports + database entries.

Usage:
    from scanner.scheduler import ScanScheduler

    scheduler = ScanScheduler()
    scheduler.add_job(
        name="nightly-dvwa",
        cron="0 2 * * *",   # 2 AM daily
        config=ScanConfig(url="http://dvwa/dvwa", ...),
    )
    scheduler.start()  # Blocks — runs until interrupted

CLI:
    python main.py --schedule "0 2 * * *" --url http://dvwa/dvwa --login-user admin --login-pass password
"""

import logging
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Optional

logger = logging.getLogger(__name__)


@dataclass
class ScheduledJob:
    """A scheduled scan job."""
    name: str
    cron: str                     # Cron expression: "min hour dom month dow"
    config: Any                   # ScanConfig object
    last_run: Optional[str] = None
    next_run: Optional[str] = None
    run_count: int = 0
    enabled: bool = True


class CronParser:
    """
    Simple cron expression parser supporting: min hour dom month dow.

    Supports: numbers, *, */N (step), comma-separated lists.
    Does not support: L, W, #, ? (enterprise cron extensions).
    """

    @staticmethod
    def matches(cron_expr: str, dt: datetime) -> bool:
        """Check if a datetime matches a cron expression."""
        parts = cron_expr.strip().split()
        if len(parts) != 5:
            raise ValueError(f"Invalid cron expression: {cron_expr} (expected 5 fields)")

        fields = [
            (parts[0], dt.minute, 0, 59),
            (parts[1], dt.hour, 0, 23),
            (parts[2], dt.day, 1, 31),
            (parts[3], dt.month, 1, 12),
            (parts[4], dt.weekday(), 0, 6),  # 0=Monday in Python
        ]

        for expr, current, lo, hi in fields:
            if not CronParser._field_matches(expr, current, lo, hi):
                return False
        return True

    @staticmethod
    def _field_matches(expr: str, current: int, lo: int, hi: int) -> bool:
        """Check if a single cron field matches the current value."""
        if expr == "*":
            return True

        for part in expr.split(","):
            part = part.strip()

            # Step: */N or N-M/S
            if "/" in part:
                base, step = part.split("/", 1)
                step = int(step)
                if base == "*":
                    if current % step == 0:
                        return True
                elif "-" in base:
                    start, end = map(int, base.split("-", 1))
                    if start <= current <= end and (current - start) % step == 0:
                        return True

            # Range: N-M
            elif "-" in part:
                start, end = map(int, part.split("-", 1))
                if start <= current <= end:
                    return True

            # Exact value
            else:
                if int(part) == current:
                    return True

        return False


class ScanScheduler:
    """
    Cron-based scan scheduler.

    Checks every 30 seconds if any jobs need to run.
    Runs scans in background threads so one slow scan
    doesn't block the schedule.
    """

    def __init__(self, check_interval: float = 30.0) -> None:
        self.check_interval = check_interval
        self.jobs: dict[str, ScheduledJob] = {}
        self._stop_event = threading.Event()
        self._running_jobs: set[str] = set()
        self._lock = threading.Lock()

    def add_job(
        self,
        name: str,
        cron: str,
        config: Any,
    ) -> None:
        """Add a scheduled scan job."""
        # Validate cron expression
        CronParser.matches(cron, datetime.now())  # Raises on invalid

        self.jobs[name] = ScheduledJob(
            name=name,
            cron=cron,
            config=config,
        )
        logger.info("Scheduled job '%s': %s", name, cron)

    def remove_job(self, name: str) -> None:
        """Remove a scheduled job."""
        self.jobs.pop(name, None)

    def start(self) -> None:
        """Start the scheduler. Blocks until stop() is called or interrupted."""
        logger.info("Scheduler started with %d job(s)", len(self.jobs))
        self._stop_event.clear()

        try:
            while not self._stop_event.is_set():
                self._check_and_run()
                self._stop_event.wait(self.check_interval)
        except KeyboardInterrupt:
            logger.info("Scheduler stopped by user")

    def start_background(self) -> threading.Thread:
        """Start the scheduler in a background thread."""
        thread = threading.Thread(target=self.start, daemon=True)
        thread.start()
        return thread

    def stop(self) -> None:
        """Signal the scheduler to stop."""
        self._stop_event.set()

    def _check_and_run(self) -> None:
        """Check all jobs and run any that match the current time."""
        now = datetime.now(timezone.utc)

        for name, job in list(self.jobs.items()):
            if not job.enabled:
                continue

            # Skip if already running
            with self._lock:
                if name in self._running_jobs:
                    continue

            try:
                if CronParser.matches(job.cron, now):
                    # Don't re-run within the same minute
                    if job.last_run:
                        last = datetime.fromisoformat(job.last_run)
                        if (now - last).total_seconds() < 60:
                            continue

                    self._run_job(job)
            except Exception as exc:
                logger.error("Scheduler error for job '%s': %s", name, exc)

    def _run_job(self, job: ScheduledJob) -> None:
        """Run a scan job in a background thread."""
        with self._lock:
            self._running_jobs.add(job.name)

        job.last_run = datetime.now(timezone.utc).isoformat()
        job.run_count += 1
        logger.info("Running scheduled job '%s' (run #%d)", job.name, job.run_count)

        thread = threading.Thread(
            target=self._execute_scan,
            args=(job,),
            daemon=True,
        )
        thread.start()

    def _execute_scan(self, job: ScheduledJob) -> None:
        """Execute the scan for a job."""
        try:
            from scanner.core import WebVulnScanner

            scanner = WebVulnScanner(
                url=job.config.url,
                config=job.config,
                scan_id=f"sched-{job.name}-{job.run_count}",
            )
            scanner.scan()
            logger.info("Scheduled job '%s' completed", job.name)

        except Exception as exc:
            logger.error("Scheduled job '%s' failed: %s", job.name, exc)

        finally:
            with self._lock:
                self._running_jobs.discard(job.name)

    def get_status(self) -> list[dict[str, Any]]:
        """Get status of all scheduled jobs."""
        status = []
        for name, job in self.jobs.items():
            with self._lock:
                running = name in self._running_jobs
            status.append({
                "name": name,
                "cron": job.cron,
                "enabled": job.enabled,
                "running": running,
                "last_run": job.last_run,
                "run_count": job.run_count,
                "target": job.config.url if hasattr(job.config, "url") else "",
            })
        return status
