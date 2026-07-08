from __future__ import annotations
"""
scanner/testers/base.py
------------------------
Abstract base class for all vulnerability testers.

Design pattern: Template Method
  BaseTester defines the contract (run() → list[Finding]) and provides
  shared utilities (payload injection, response comparison, URL building).
  Concrete testers (SQLiTester, XSSTester, CSRFTester) only implement their
  specific detection logic.

  This makes the system easy to extend — adding a new vulnerability type
  means creating a new class that inherits from BaseTester and implements run().
"""

import fnmatch
import logging
from abc import ABC, abstractmethod
from urllib.parse import urlencode, urlparse, parse_qs, urlunparse

from scanner.crawler import CrawledForm, CrawledPage
from scanner.reporting.models import Finding

logger = logging.getLogger(__name__)

# Module-level scope patterns — set by the scanner core before testers run
_scope_include: list[str] = []
_scope_exclude: list[str] = []


def set_scope_patterns(include: list[str], exclude: list[str]) -> None:
    """Configure URL scope patterns (fnmatch globs) for all testers."""
    global _scope_include, _scope_exclude
    _scope_include = include
    _scope_exclude = exclude


def is_url_in_scope(url: str) -> bool:
    """Check if a URL matches scope include/exclude patterns."""
    # If no include patterns, everything is in scope
    if _scope_include:
        if not any(fnmatch.fnmatch(url, pat) for pat in _scope_include):
            return False

    # Check exclusions
    if _scope_exclude:
        if any(fnmatch.fnmatch(url, pat) for pat in _scope_exclude):
            return False

    return True


class BaseTester(ABC):
    """
    Abstract base for all vulnerability testers.

    Subclasses MUST implement:
        run(pages) → list[Finding]

    Subclasses SHOULD call super().__init__() to register shared config.
    """

    def __init__(self, name: str) -> None:
        """
        Args:
            name : Human-readable tester name used in log messages / UI.
        """
        self.name     = name
        self.findings: list[Finding] = []
        self._params_tested: int = 0

    @property
    def params_tested(self) -> int:
        return self._params_tested

    # ------------------------------------------------------------------
    # Contract — every tester implements this
    # ------------------------------------------------------------------

    @abstractmethod
    def run(self, pages: list[CrawledPage]) -> list[Finding]:
        """
        Execute all tests against the provided crawled pages.

        Args:
            pages : CrawledPage objects from the Crawler.

        Returns:
            List of Finding objects for every confirmed vulnerability.
        """
        ...

    # ------------------------------------------------------------------
    # Shared helpers — available to all subclasses
    # ------------------------------------------------------------------

    def _inject_form(
        self,
        form: CrawledForm,
        target_field: str,
        payload: str,
    ) -> dict:
        """
        Build a form data dict with `payload` injected into `target_field`.
        All other fields retain their original values so the form submits
        cleanly and hidden/CSRF fields aren't disturbed.

        Args:
            form         : The CrawledForm to build data for.
            target_field : The field name to inject the payload into.
            payload      : The attack string to insert.

        Returns:
            A dict suitable for requests.post(data=...) or requests.get(params=...).

        Security concept:
            During a real pentest, you inject payloads one parameter at a time
            while keeping other parameters benign. This isolates which parameter
            is vulnerable and avoids false positives from interaction effects.
        """
        data = {}
        for f in form.fields:
            if f.name == target_field:
                data[f.name] = payload
            else:
                data[f.name] = f.value  # preserve original value
        return data

    def _inject_get_param(
        self,
        url: str,
        target_param: str,
        payload: str,
    ) -> str:
        """
        Return a new URL with `payload` substituted into `target_param`.

        Example:
            url   = "http://example.com/search?q=hello&page=1"
            param = "q"
            payload = "' OR '1'='1"
            → "http://example.com/search?q=%27+OR+%271%27%3D%271&page=1"

        All other query parameters are preserved unchanged.
        """
        parsed  = urlparse(url)
        params  = parse_qs(parsed.query, keep_blank_values=True)

        # Overwrite target param; keep everything else
        params[target_param] = [payload]

        new_query = urlencode(params, doseq=True)
        return urlunparse(parsed._replace(query=new_query))

    def _extract_error_snippet(self, text: str, keyword: str, window: int = 150) -> str:
        """
        Find `keyword` in `text` and return up to `window` characters of
        surrounding context. Used to produce short evidence snippets.

        Args:
            text    : Full response body.
            keyword : String to locate.
            window  : Characters of context on each side.

        Returns:
            Snippet string, or empty string if keyword not found.
        """
        idx = text.lower().find(keyword.lower())
        if idx == -1:
            return ""
        start = max(0, idx - 30)
        end   = min(len(text), idx + window)
        return text[start:end].strip()

    def _is_in_scope(self, url: str) -> bool:
        """Check if a URL is within the configured scan scope."""
        return is_url_in_scope(url)

    def _filter_pages_by_scope(self, pages: list[CrawledPage]) -> list[CrawledPage]:
        """Filter pages to only those within the configured scope."""
        if not _scope_include and not _scope_exclude:
            return pages
        return [p for p in pages if self._is_in_scope(p.url)]

    def _log_finding(self, finding: Finding) -> None:
        """Record a finding and log it at WARNING level.
        Skips findings for out-of-scope URLs."""
        if not self._is_in_scope(finding.url):
            logger.debug("Skipping out-of-scope finding: %s", finding.url)
            return

        self.findings.append(finding)
        logger.warning(
            "[%s] %s found at %s param=%s",
            finding.severity,
            finding.vuln_type,
            finding.url,
            finding.parameter,
        )

    def _count_test(self) -> None:
        """Increment the parameters-tested counter."""
        self._params_tested += 1
