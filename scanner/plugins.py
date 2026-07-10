from __future__ import annotations
"""
scanner/plugins.py
--------------------
Plugin system for dynamically loading custom vulnerability testers.

Enterprise users can add their own testers by placing Python files in
a plugins directory. Each plugin module must define a class that
inherits from BaseTester.

Plugin discovery:
  1. Scans configured directories for .py files
  2. Imports each module dynamically
  3. Finds all BaseTester subclasses in the module
  4. Registers them in the tester map

Usage:
    from scanner.plugins import PluginManager

    pm = PluginManager(directories=["plugins", "/opt/w3bsp1d3r/plugins"])
    custom_testers = pm.discover()

    # Returns a dict of {name: TesterClass}
    for name, cls in custom_testers.items():
        tester = cls()
        findings = tester.run(pages)

Plugin file example (plugins/my_tester.py):

    from scanner.testers.base import BaseTester
    from scanner.crawler import CrawledPage
    from scanner.reporting.models import Finding

    class MyCustomTester(BaseTester):
        def __init__(self):
            super().__init__(name="My Custom Tester")

        def run(self, pages: list[CrawledPage]) -> list[Finding]:
            # Custom detection logic
            return self.findings
"""

import importlib.util
import inspect
import logging
import sys
from pathlib import Path

from scanner.testers.base import BaseTester

logger = logging.getLogger(__name__)


class PluginManager:
    """
    Discovers and loads custom vulnerability tester plugins.

    Plugins are Python modules containing classes that inherit from BaseTester.
    They are loaded dynamically at runtime from configured directories.
    """

    def __init__(
        self,
        directories: list[str] | None = None,
        enabled: bool = True,
    ) -> None:
        self.directories = [Path(d) for d in (directories or ["plugins"])]
        self.enabled = enabled
        self._loaded: dict[str, type[BaseTester]] = {}
        self._errors: list[dict] = []

    def discover(self) -> dict[str, type[BaseTester]]:
        """
        Scan plugin directories and load all valid tester classes.

        Returns a dict mapping tester name (lowercase) to tester class.
        """
        if not self.enabled:
            return {}

        for directory in self.directories:
            if not directory.exists():
                logger.debug("Plugin directory does not exist: %s", directory)
                continue

            if not directory.is_dir():
                logger.warning("Plugin path is not a directory: %s", directory)
                continue

            for py_file in sorted(directory.glob("*.py")):
                if py_file.name.startswith("_"):
                    continue
                self._load_module(py_file)

        if self._loaded:
            logger.info(
                "Loaded %d plugin tester(s): %s",
                len(self._loaded),
                ", ".join(self._loaded.keys()),
            )

        return dict(self._loaded)

    def _load_module(self, path: Path) -> None:
        """Load a single plugin module and extract BaseTester subclasses."""
        module_name = f"w3bsp1d3r_plugin_{path.stem}"

        try:
            spec = importlib.util.spec_from_file_location(module_name, path)
            if spec is None or spec.loader is None:
                logger.warning("Could not create module spec for %s", path)
                return

            module = importlib.util.module_from_spec(spec)

            # Prevent plugin from polluting sys.modules permanently
            sys.modules[module_name] = module

            try:
                spec.loader.exec_module(module)
            except Exception as exc:
                logger.warning("Failed to load plugin %s: %s", path.name, exc)
                self._errors.append({
                    "file": str(path),
                    "error": str(exc),
                    "type": type(exc).__name__,
                })
                return

            # Find all BaseTester subclasses in the module
            for attr_name in dir(module):
                attr = getattr(module, attr_name)
                if (
                    inspect.isclass(attr)
                    and issubclass(attr, BaseTester)
                    and attr is not BaseTester
                    and attr.__module__ == module_name
                ):
                    # Use class name as the tester key
                    key = attr_name.lower().replace("tester", "")
                    if not key:
                        key = attr_name.lower()
                    self._loaded[key] = attr
                    logger.debug(
                        "Loaded plugin tester '%s' from %s", key, path.name,
                    )

        except Exception as exc:
            logger.warning("Unexpected error loading plugin %s: %s", path.name, exc)
            self._errors.append({
                "file": str(path),
                "error": str(exc),
                "type": type(exc).__name__,
            })

    @property
    def errors(self) -> list[dict]:
        """Return a list of plugin loading errors."""
        return list(self._errors)

    def get_loaded_plugins(self) -> dict[str, str]:
        """Return a dict of loaded plugin names and their source files."""
        return {
            name: inspect.getfile(cls)
            for name, cls in self._loaded.items()
        }
