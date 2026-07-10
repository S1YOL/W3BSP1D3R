from __future__ import annotations
"""
scanner/virustotal.py
----------------------
VirusTotal API v3 integration.

Checks the target domain and discovered URLs against VirusTotal's threat
intelligence database. If any crawled page serves downloadable files
(zip, exe, pdf, etc.) their URLs are also submitted for analysis.

Requires a VirusTotal API key (free tier available at virustotal.com).
  Free tier:  4 requests/minute, 500 requests/day  -> use --vt-delay 15
  Premium:    higher limits suitable for enterprise scanning

API reference: https://docs.virustotal.com/reference/overview

by S1YOL.
"""

import base64
import logging
import time
from typing import Optional
from urllib.parse import urlparse

import requests

from scanner.utils.display import print_status

logger = logging.getLogger(__name__)

VT_BASE = "https://www.virustotal.com/api/v3"

# File extensions that are worth submitting to VT for malware checking
_SUSPICIOUS_EXTENSIONS = {
    ".exe", ".dll", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jar",
    ".php", ".phtml", ".asp", ".aspx",
    ".zip", ".rar", ".7z", ".tar", ".gz",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
}


class VirusTotalClient:
    """
    Lightweight VirusTotal API v3 client.

    Usage:
        vt = VirusTotalClient(api_key="your_key")
        result = vt.check_domain("example.com")
        result = vt.check_url("https://example.com/page")
    """

    def __init__(self, api_key: str, request_delay: float = 15.0) -> None:
        """
        Args:
            api_key       : VirusTotal API key.
            request_delay : Seconds to wait between VT requests.
                            Free tier requires ~15s (4 req/min).
        """
        self.api_key = api_key
        self.delay   = request_delay
        self._session = requests.Session()
        self._session.headers["x-apikey"] = api_key
        self._last_request = 0.0

    def check_domain(self, domain: str) -> Optional[dict]:
        """
        Fetch domain reputation from VirusTotal.
        Returns a normalized summary dict or None on failure.
        """
        data = self._get(f"domains/{domain}")
        if not data:
            return None
        return self._parse_stats(data, resource=domain, resource_type="domain")

    def check_url(self, url: str) -> Optional[dict]:
        """
        Fetch URL analysis from VirusTotal.
        VT identifies URLs by their base64url-encoded form.
        """
        url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
        data = self._get(f"urls/{url_id}")
        if not data:
            return None
        return self._parse_stats(data, resource=url, resource_type="url")

    def check_file_url(self, url: str) -> Optional[dict]:
        """
        Check a URL that points to a downloadable file.
        Uses the URL lookup endpoint — does NOT download the file.
        """
        return self.check_url(url)

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _get(self, endpoint: str) -> Optional[dict]:
        """Rate-limited GET. Returns parsed JSON or None."""
        self._rate_wait()
        try:
            resp = self._session.get(f"{VT_BASE}/{endpoint}", timeout=30)
            self._last_request = time.monotonic()
            if resp.status_code == 200:
                return resp.json()
            elif resp.status_code == 404:
                logger.debug("VT: not found — %s", endpoint)
            elif resp.status_code == 429:
                logger.warning("VT rate limit hit — increase --vt-delay")
            elif resp.status_code == 401:
                logger.error("VT: invalid API key")
            else:
                logger.warning("VT: HTTP %d for %s", resp.status_code, endpoint)
        except Exception as exc:
            logger.warning("VT request failed: %s", exc)
        return None

    def _rate_wait(self) -> None:
        elapsed = time.monotonic() - self._last_request
        if elapsed < self.delay:
            time.sleep(self.delay - elapsed)

    def _parse_stats(self, data: dict, resource: str, resource_type: str) -> dict:
        """Extract last_analysis_stats from a VT API response."""
        try:
            attrs = data.get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            return {
                "resource":      resource,
                "resource_type": resource_type,
                "malicious":     stats.get("malicious", 0),
                "suspicious":    stats.get("suspicious", 0),
                "harmless":      stats.get("harmless", 0),
                "undetected":    stats.get("undetected", 0),
                "total_engines": sum(stats.values()),
                "reputation":    attrs.get("reputation", 0),
                "categories":    attrs.get("categories", {}),
                "tags":          attrs.get("tags", []),
            }
        except Exception as exc:
            logger.debug("VT parse error: %s", exc)
            return {}


def scan_target(
    base_url: str,
    crawled_urls: list[str],
    api_key: str,
    request_delay: float = 15.0,
) -> list[dict]:
    """
    Run VirusTotal checks against the target domain and any suspicious file URLs.

    Args:
        base_url      : The scanner's primary target URL.
        crawled_urls  : All URLs discovered during crawling.
        api_key       : VirusTotal API key.
        request_delay : Delay between VT API requests.

    Returns:
        List of result dicts for flagged resources (malicious or suspicious > 0).
    """
    vt = VirusTotalClient(api_key, request_delay)
    flagged: list[dict] = []

    # 1. Check the target domain
    domain = urlparse(base_url).netloc
    print_status(f"VirusTotal: checking domain {domain}")
    result = vt.check_domain(domain)
    if result:
        _evaluate(result, flagged)

    # 2. Check the target URL itself
    print_status("VirusTotal: checking target URL")
    result = vt.check_url(base_url)
    if result:
        _evaluate(result, flagged)

    # 3. Check any file URLs found during crawling
    file_urls = [
        u for u in crawled_urls
        if any(urlparse(u).path.lower().endswith(ext) for ext in _SUSPICIOUS_EXTENSIONS)
    ]
    if file_urls:
        print_status(f"VirusTotal: checking {len(file_urls)} file URL(s)")
    for url in file_urls[:20]:  # cap at 20 to respect rate limits
        result = vt.check_file_url(url)
        if result:
            _evaluate(result, flagged)

    if not flagged:
        print_status("VirusTotal: no threats detected")

    return flagged


def _evaluate(result: dict, flagged: list[dict]) -> None:
    """Add result to flagged list if any engine flagged it as malicious/suspicious."""
    if result.get("malicious", 0) > 0 or result.get("suspicious", 0) > 0:
        flagged.append(result)
        logger.warning(
            "VT flagged %s (%s): malicious=%d suspicious=%d",
            result.get("resource"),
            result.get("resource_type"),
            result.get("malicious", 0),
            result.get("suspicious", 0),
        )
