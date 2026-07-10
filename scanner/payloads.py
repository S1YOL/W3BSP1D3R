from __future__ import annotations
"""
scanner/payloads.py
---------------------
Custom payload loader for enterprise users.

Loads attack payloads from external YAML or JSON files, allowing
security teams to maintain their own payload libraries without
modifying scanner source code.

Payload files are organized by vulnerability type and can include:
  - Custom SQLi payloads for specific databases
  - Organization-specific XSS vectors
  - WAF bypass payloads tuned to the target
  - Industry-specific test strings

File format (YAML):

    sqli:
      error:
        - "' OR '1'='1"
        - "1; DROP TABLE users--"
      boolean:
        - true: "' OR 1=1--"
          false: "' OR 1=2--"
    xss:
      reflected:
        - "<script>alert(1)</script>"
        - "<img src=x onerror=alert(1)>"
    cmdi:
      - "; id"
      - "| cat /etc/passwd"

Usage:
    from scanner.payloads import PayloadManager

    pm = PayloadManager()
    pm.load_file("custom_payloads.yaml")
    pm.load_directory("payloads/")

    sqli_payloads = pm.get("sqli.error")
    xss_payloads = pm.get("xss.reflected")
"""

import json
import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


class PayloadManager:
    """
    Manages custom payload loading from external files.

    Payloads are organized in a nested dict and accessed via
    dot-notation keys (e.g. "sqli.error", "xss.reflected").
    """

    def __init__(self) -> None:
        self._payloads: dict[str, Any] = {}
        self._sources: list[str] = []

    def load_file(self, path: str | Path) -> int:
        """
        Load payloads from a YAML or JSON file.

        Returns the number of payload categories loaded.
        """
        path = Path(path)
        if not path.exists():
            logger.warning("Payload file not found: %s", path)
            return 0

        try:
            if path.suffix in (".yaml", ".yml"):
                import yaml
                with path.open("r", encoding="utf-8") as fh:
                    data = yaml.safe_load(fh)
            elif path.suffix == ".json":
                with path.open("r", encoding="utf-8") as fh:
                    data = json.load(fh)
            else:
                logger.warning("Unsupported payload file format: %s", path.suffix)
                return 0

            if not isinstance(data, dict):
                logger.warning("Payload file must be a mapping: %s", path)
                return 0

            count = self._merge(data)
            self._sources.append(str(path))
            logger.info("Loaded %d payload categories from %s", count, path.name)
            return count

        except Exception as exc:
            logger.warning("Failed to load payload file %s: %s", path, exc)
            return 0

    def load_directory(self, directory: str | Path) -> int:
        """
        Load all YAML and JSON payload files from a directory.

        Returns total number of categories loaded.
        """
        directory = Path(directory)
        if not directory.is_dir():
            logger.warning("Payload directory not found: %s", directory)
            return 0

        total = 0
        for pattern in ("*.yaml", "*.yml", "*.json"):
            for path in sorted(directory.glob(pattern)):
                if path.name.startswith("_"):
                    continue
                total += self.load_file(path)

        return total

    def get(self, key: str, default: list | None = None) -> list:
        """
        Get payloads by dot-notation key.

        Examples:
            pm.get("sqli.error")        → ["' OR '1'='1", ...]
            pm.get("xss.reflected")     → ["<script>...", ...]
            pm.get("cmdi")              → ["; id", ...]
        """
        parts = key.split(".")
        current = self._payloads

        for part in parts:
            if isinstance(current, dict) and part in current:
                current = current[part]
            else:
                return default if default is not None else []

        if isinstance(current, list):
            return current
        if isinstance(current, dict):
            # Flatten all sub-lists into one list
            result = []
            self._flatten(current, result)
            return result

        return [current] if current else (default or [])

    def has(self, key: str) -> bool:
        """Check if a payload category exists."""
        return bool(self.get(key))

    def categories(self) -> list[str]:
        """List all top-level payload categories."""
        return list(self._payloads.keys())

    def stats(self) -> dict[str, Any]:
        """Get payload statistics."""
        total = 0
        cats = {}
        for key, value in self._payloads.items():
            count = self._count_payloads(value)
            cats[key] = count
            total += count

        return {
            "total_payloads": total,
            "categories": cats,
            "sources": self._sources,
        }

    def _merge(self, data: dict, prefix: str = "") -> int:
        """Merge loaded data into the internal payload store."""
        count = 0
        for key, value in data.items():
            if key in self._payloads and isinstance(self._payloads[key], dict) and isinstance(value, dict):
                # Deep merge
                count += self._merge(value, f"{prefix}{key}.")
                self._payloads[key].update(value)
            else:
                self._payloads[key] = value
                count += 1
        return count

    def _flatten(self, d: dict, result: list) -> None:
        """Recursively flatten nested dicts into a single list."""
        for value in d.values():
            if isinstance(value, list):
                result.extend(value)
            elif isinstance(value, dict):
                self._flatten(value, result)
            else:
                result.append(value)

    def _count_payloads(self, obj: Any) -> int:
        """Count total payload strings in a nested structure."""
        if isinstance(obj, list):
            return len(obj)
        if isinstance(obj, dict):
            return sum(self._count_payloads(v) for v in obj.values())
        return 1
