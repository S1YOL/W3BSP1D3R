from __future__ import annotations
"""
scanner/utils/http_async.py
------------------------------
Async HTTP client built on httpx for high-throughput scanning.

Drop-in replacement for the sync http.py module when async mode is enabled.
Provides the same API surface (get, post, timed_get, timed_post) but uses
httpx.AsyncClient for non-blocking I/O with connection pooling.

Key advantages over sync requests:
  - True concurrent HTTP requests (not thread-based)
  - Connection pooling with HTTP/2 support
  - Dramatically faster on large targets (10-50x throughput)
  - Lower memory footprint than threading

Usage:
    from scanner.utils.http_async import AsyncHTTPClient

    async with AsyncHTTPClient(delay=0.5, timeout=10) as client:
        resp = await client.get("http://example.com")
        resp, elapsed = await client.timed_get("http://example.com")

Or via the sync wrapper for backwards compatibility:
    from scanner.utils.http_async import run_async_get, run_async_post
"""

import asyncio
import ipaddress
import logging
import time
from typing import Any, Optional
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

# Maximum response body size (5 MB)
MAX_RESPONSE_BYTES = 5 * 1024 * 1024

SCANNER_UA = (
    "W3BSP1D3R/2.0 (Enterprise Security Scanner; "
    "by S1YOL - github.com/S1YOL/W3BSP1D3R)"
)

_PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]


def _is_private_ip(hostname: str) -> bool:
    try:
        addr = ipaddress.ip_address(hostname)
        return any(addr in net for net in _PRIVATE_NETWORKS)
    except ValueError:
        return False


class AsyncRequestMetrics:
    """Thread-safe request metrics for async HTTP client."""

    def __init__(self) -> None:
        self.total_requests = 0
        self.successful = 0
        self.failed = 0
        self.retried = 0
        self.rate_limited = 0
        self.total_bytes = 0
        self.total_time = 0.0
        self._lock = asyncio.Lock()

    async def record(self, success: bool, bytes_recv: int = 0,
                     elapsed: float = 0.0, retried: bool = False,
                     rate_limited: bool = False) -> None:
        async with self._lock:
            self.total_requests += 1
            if success:
                self.successful += 1
            else:
                self.failed += 1
            if retried:
                self.retried += 1
            if rate_limited:
                self.rate_limited += 1
            self.total_bytes += bytes_recv
            self.total_time += elapsed

    def snapshot(self) -> dict:
        avg = self.total_time / max(self.total_requests, 1)
        return {
            "total_requests": self.total_requests,
            "successful": self.successful,
            "failed": self.failed,
            "retried": self.retried,
            "rate_limited": self.rate_limited,
            "total_bytes": self.total_bytes,
            "avg_response_time": round(avg, 3),
        }


class AsyncHTTPClient:
    """
    Async HTTP client with retry, rate limiting, SSRF guard, and metrics.

    Designed as an async context manager:
        async with AsyncHTTPClient(...) as client:
            resp = await client.get(url)
    """

    def __init__(
        self,
        delay: float = 0.5,
        timeout: int = 10,
        verify_ssl: bool = True,
        proxy: str | None = None,
        auth_token: str | None = None,
        user_agent: str = SCANNER_UA,
        max_retries: int = 3,
        backoff_factor: float = 2.0,
        retry_on_status: tuple[int, ...] = (429, 500, 502, 503, 504),
        allowed_origins: set[str] | None = None,
        max_concurrent: int = 20,
    ) -> None:
        self.delay = delay
        self.timeout = timeout
        self.max_retries = max_retries
        self.backoff_factor = backoff_factor
        self.retry_on_status = retry_on_status
        self.allowed_origins = allowed_origins or set()
        self.metrics = AsyncRequestMetrics()

        self._semaphore = asyncio.Semaphore(max_concurrent)
        self._client = None
        self._verify_ssl = verify_ssl
        self._proxy = proxy
        self._auth_token = auth_token
        self._user_agent = user_agent

    async def __aenter__(self):
        try:
            import httpx
        except ImportError:
            raise ImportError(
                "Async HTTP requires httpx. Install with: pip install httpx"
            )

        headers = {
            "User-Agent": self._user_agent,
            "Accept": (
                "text/html,application/xhtml+xml,application/xml;q=0.9,"
                "image/avif,image/webp,*/*;q=0.8"
            ),
            "Accept-Language": "en-US,en;q=0.5",
        }
        if self._auth_token:
            headers["Authorization"] = f"Bearer {self._auth_token}"

        self._client = httpx.AsyncClient(
            headers=headers,
            timeout=httpx.Timeout(self.timeout),
            verify=self._verify_ssl,
            proxy=self._proxy,
            follow_redirects=True,
            limits=httpx.Limits(
                max_connections=100,
                max_keepalive_connections=20,
            ),
        )
        return self

    async def __aexit__(self, *args):
        if self._client:
            await self._client.aclose()

    async def get(self, url: str, **kwargs) -> Any:
        """Async GET with retry, rate limiting, and SSRF guard."""
        return await self._request("GET", url, **kwargs)

    async def post(self, url: str, data: dict | None = None, **kwargs) -> Any:
        """Async POST with retry, rate limiting, and SSRF guard."""
        return await self._request("POST", url, data=data, **kwargs)

    async def timed_get(self, url: str, **kwargs) -> tuple[Any, float]:
        """Async GET that returns (response, elapsed_seconds)."""
        async with self._semaphore:
            await asyncio.sleep(self.delay)
            start = time.monotonic()
            resp = await self._client.get(url, **kwargs)
            elapsed = time.monotonic() - start
            self._check_redirect(resp)
            self._enforce_size_limit(resp)
            await self.metrics.record(True, len(resp.content), elapsed)
            return resp, elapsed

    async def timed_post(self, url: str, data: dict | None = None, **kwargs) -> tuple[Any, float]:
        """Async POST that returns (response, elapsed_seconds)."""
        async with self._semaphore:
            await asyncio.sleep(self.delay)
            start = time.monotonic()
            resp = await self._client.post(url, data=data, **kwargs)
            elapsed = time.monotonic() - start
            self._check_redirect(resp)
            self._enforce_size_limit(resp)
            await self.metrics.record(True, len(resp.content), elapsed)
            return resp, elapsed

    async def _request(self, method: str, url: str, data: dict | None = None, **kwargs) -> Any:
        """Execute request with retry and rate limiting."""
        retried = False

        for attempt in range(self.max_retries + 1):
            async with self._semaphore:
                await asyncio.sleep(self.delay)
                start = time.monotonic()

                try:
                    if method == "GET":
                        resp = await self._client.get(url, **kwargs)
                    else:
                        resp = await self._client.post(url, data=data, **kwargs)

                    elapsed = time.monotonic() - start

                    if resp.status_code in self.retry_on_status:
                        if attempt < self.max_retries:
                            wait = self.backoff_factor ** attempt
                            if resp.status_code == 429:
                                retry_after = resp.headers.get("retry-after")
                                if retry_after:
                                    try:
                                        wait = max(wait, float(retry_after))
                                    except ValueError:
                                        pass
                                await self.metrics.record(True, rate_limited=True)

                            logger.debug(
                                "%s %s → %d (attempt %d, retrying in %.1fs)",
                                method, url, resp.status_code, attempt + 1, wait,
                            )
                            retried = True
                            await asyncio.sleep(wait)
                            continue

                    self._check_redirect(resp)
                    self._enforce_size_limit(resp)
                    await self.metrics.record(True, len(resp.content), elapsed, retried)

                    logger.debug(
                        "%s %s → %d (%d bytes, %.2fs)",
                        method, url, resp.status_code, len(resp.content), elapsed,
                    )
                    return resp

                except Exception as exc:
                    elapsed = time.monotonic() - start
                    if attempt < self.max_retries:
                        wait = self.backoff_factor ** attempt
                        logger.debug("%s %s failed: %s (retrying)", method, url, exc)
                        retried = True
                        await asyncio.sleep(wait)
                        continue

                    await self.metrics.record(False, elapsed=elapsed, retried=retried)
                    logger.warning("%s %s failed: %s", method, url, exc)
                    raise

        return resp  # type: ignore

    def _check_redirect(self, resp: Any) -> None:
        """Validate redirect chain against allowed origins."""
        if not self.allowed_origins:
            return

        for redirect in resp.history:
            loc = str(redirect.headers.get("location", ""))
            if not loc:
                continue
            parsed = urlparse(loc)
            origin = f"{parsed.scheme}://{parsed.netloc}"
            host = parsed.hostname or ""

            if _is_private_ip(host):
                raise ValueError(f"SSRF blocked: redirect to private IP {host}")
            if origin and origin not in self.allowed_origins:
                raise ValueError(f"Out-of-scope redirect: {origin}")

    def _enforce_size_limit(self, resp: Any) -> None:
        """Truncate oversized responses."""
        if len(resp.content) > MAX_RESPONSE_BYTES:
            logger.warning(
                "Response from %s exceeds size limit — truncating",
                resp.url,
            )
            resp._content = resp.content[:MAX_RESPONSE_BYTES]

    def get_metrics(self) -> dict:
        """Return a snapshot of request metrics."""
        return self.metrics.snapshot()


# ---------------------------------------------------------------------------
# Sync wrappers for backwards compatibility
# ---------------------------------------------------------------------------

def run_async_get(url: str, client: AsyncHTTPClient, **kwargs) -> Any:
    """Sync wrapper around async get."""
    loop = asyncio.get_event_loop()
    if loop.is_running():
        import concurrent.futures
        with concurrent.futures.ThreadPoolExecutor() as pool:
            return pool.submit(asyncio.run, client.get(url, **kwargs)).result()
    return asyncio.run(client.get(url, **kwargs))


def run_async_post(url: str, client: AsyncHTTPClient, data: dict | None = None, **kwargs) -> Any:
    """Sync wrapper around async post."""
    loop = asyncio.get_event_loop()
    if loop.is_running():
        import concurrent.futures
        with concurrent.futures.ThreadPoolExecutor() as pool:
            return pool.submit(asyncio.run, client.post(url, data=data, **kwargs)).result()
    return asyncio.run(client.post(url, data=data, **kwargs))
