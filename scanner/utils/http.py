from __future__ import annotations
"""
scanner/utils/http.py
----------------------
HTTP engine with per-scan isolation.

All mutable HTTP state (session config, cookie jar, SSRF scope, rate limiter,
retry policy, adaptive back-off, metrics) is encapsulated in an ``HttpClient``
instance. Each scan owns its own client, so two scans running concurrently
(e.g. via the REST API) cannot clobber each other's scope, cookies, or limits.

The 25 testers and the crawler keep calling the module-level helpers
(``http_utils.get``/``post``/``timed_get``/``timed_post``/``get_session`` …).
Those helpers resolve the *current* client from a ``ContextVar``:

  * ``WebVulnScanner.scan()`` sets its client as current on the orchestrating
    thread and re-sets it inside each worker thread.
  * If no client is set (e.g. unit tests calling ``init_session()`` directly),
    a module-level default client is used — fully backwards compatible.

Design highlights carried over from before:
  - Per-thread ``requests.Session`` (real concurrency, no shared-session lock),
    with a lock-protected shared cookie jar so auth state propagates.
  - SSRF guard on redirects, response-size cap, retry + adaptive rate limiting,
    token-bucket pacing, and request metrics.
"""

import contextvars
import ipaddress
import threading
import time
import logging
from typing import Optional
from urllib.parse import urlparse

import requests
from requests import Response, Session

logger = logging.getLogger(__name__)

# Default scanner identity string — be transparent about what you are
SCANNER_UA = (
    "W3BSP1D3R/3.0 (Authorised Security Testing Tool; "
    "by S1YOL - github.com/siyol/web-vuln-scanner)"
)

# Default delays (seconds) — configurable at init time
DEFAULT_DELAY   = 0.5   # between every request
DEFAULT_TIMEOUT = 10    # per-request timeout

# Maximum response body size — prevents OOM from malicious targets (5 MB)
MAX_RESPONSE_BYTES = 5 * 1024 * 1024

# Private/reserved IP ranges that redirects must never reach (SSRF protection)
_PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),   # link-local / AWS metadata
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]


# ---------------------------------------------------------------------------
# Request metrics — thread-safe counters
# ---------------------------------------------------------------------------

class RequestMetrics:
    """Thread-safe request/response metrics for observability."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.total_requests = 0
        self.successful_requests = 0
        self.failed_requests = 0
        self.retried_requests = 0
        self.rate_limited_count = 0
        self.total_bytes_received = 0
        self.total_response_time = 0.0

    def record_request(self, success: bool, bytes_received: int = 0,
                       response_time: float = 0.0, retried: bool = False,
                       rate_limited: bool = False) -> None:
        with self._lock:
            self.total_requests += 1
            if success:
                self.successful_requests += 1
            else:
                self.failed_requests += 1
            if retried:
                self.retried_requests += 1
            if rate_limited:
                self.rate_limited_count += 1
            self.total_bytes_received += bytes_received
            self.total_response_time += response_time

    def snapshot(self) -> dict:
        with self._lock:
            avg_time = (
                self.total_response_time / self.total_requests
                if self.total_requests > 0 else 0.0
            )
            return {
                "total_requests": self.total_requests,
                "successful": self.successful_requests,
                "failed": self.failed_requests,
                "retried": self.retried_requests,
                "rate_limited": self.rate_limited_count,
                "total_bytes": self.total_bytes_received,
                "avg_response_time": round(avg_time, 3),
            }


# ---------------------------------------------------------------------------
# Token bucket rate limiter
# ---------------------------------------------------------------------------

class TokenBucket:
    """
    Token bucket algorithm for smooth rate limiting.

    Allows bursts up to `capacity` requests, then throttles to
    `fill_rate` requests per second.
    """

    def __init__(self, capacity: float, fill_rate: float) -> None:
        self.capacity = capacity
        self.fill_rate = fill_rate
        self._tokens = capacity
        self._last_fill = time.monotonic()
        self._lock = threading.Lock()

    def acquire(self, timeout: float = 30.0) -> bool:
        """
        Block until a token is available or timeout is reached.
        Returns True if a token was acquired, False on timeout.
        """
        deadline = time.monotonic() + timeout
        while True:
            with self._lock:
                self._refill()
                if self._tokens >= 1.0:
                    self._tokens -= 1.0
                    return True
            if time.monotonic() >= deadline:
                return False
            with self._lock:
                wait = (1.0 - self._tokens) / self.fill_rate
            time.sleep(min(wait, 0.1))

    def _refill(self) -> None:
        now = time.monotonic()
        elapsed = now - self._last_fill
        self._tokens = min(self.capacity, self._tokens + elapsed * self.fill_rate)
        self._last_fill = now


# ---------------------------------------------------------------------------
# Retry configuration
# ---------------------------------------------------------------------------

class RetryConfig:
    """Configuration for retry behaviour."""

    def __init__(
        self,
        max_retries: int = 3,
        backoff_factor: float = 2.0,
        max_backoff: float = 60.0,
        retry_on_status: tuple[int, ...] = (429, 500, 502, 503, 504),
        adaptive: bool = True,
    ) -> None:
        self.max_retries = max_retries
        self.backoff_factor = backoff_factor
        self.max_backoff = max_backoff
        self.retry_on_status = retry_on_status
        self.adaptive = adaptive


# ---------------------------------------------------------------------------
# Stateless helpers (safe to import directly)
# ---------------------------------------------------------------------------

def _is_private_ip(hostname: str) -> bool:
    """Return True if hostname is a private/reserved IP."""
    try:
        addr = ipaddress.ip_address(hostname)
        return any(addr in net for net in _PRIVATE_NETWORKS)
    except ValueError:
        return False


def _enforce_size_limit(resp: Response) -> None:
    """Truncate response content if it exceeds MAX_RESPONSE_BYTES."""
    if len(resp.content) > MAX_RESPONSE_BYTES:
        logger.warning(
            "Response from %s exceeds %d bytes (%d) — truncating",
            resp.url, MAX_RESPONSE_BYTES, len(resp.content),
        )
        resp._content = resp.content[:MAX_RESPONSE_BYTES]


# ---------------------------------------------------------------------------
# HttpClient — owns ALL per-scan HTTP state
# ---------------------------------------------------------------------------

class HttpClient:
    """Self-contained HTTP engine for a single scan (isolated from other scans)."""

    def __init__(
        self,
        delay: float = DEFAULT_DELAY,
        timeout: int = DEFAULT_TIMEOUT,
        user_agent: str = SCANNER_UA,
        verify_ssl: bool = True,
        proxy: str | None = None,
        auth_token: str | None = None,
        max_retries: int = 3,
        backoff_factor: float = 2.0,
        adaptive_rate_limit: bool = True,
        retry_on_status: tuple[int, ...] | None = None,
    ) -> None:
        self.metrics = RequestMetrics()
        self.allowed_origins: set[str] = set()
        self._thread_local = threading.local()
        self._generation = 0
        self._config_lock = threading.Lock()
        self._cookie_lock = threading.Lock()
        self._shared_cookies = requests.cookies.RequestsCookieJar()
        self._settings: dict = {}
        self._adaptive_delay = 0.0
        self._adaptive_lock = threading.Lock()
        self.delay = delay
        self.timeout = timeout
        self.retry_config = RetryConfig()
        self.rate_limiter: Optional[TokenBucket] = None
        self.configure(
            delay=delay, timeout=timeout, user_agent=user_agent,
            verify_ssl=verify_ssl, proxy=proxy, auth_token=auth_token,
            max_retries=max_retries, backoff_factor=backoff_factor,
            adaptive_rate_limit=adaptive_rate_limit, retry_on_status=retry_on_status,
        )

    # -- configuration --------------------------------------------------

    def configure(
        self,
        delay: float = DEFAULT_DELAY,
        timeout: int = DEFAULT_TIMEOUT,
        user_agent: str = SCANNER_UA,
        verify_ssl: bool = True,
        proxy: str | None = None,
        auth_token: str | None = None,
        max_retries: int = 3,
        backoff_factor: float = 2.0,
        adaptive_rate_limit: bool = True,
        retry_on_status: tuple[int, ...] | None = None,
    ) -> Session:
        self.delay = delay
        self.timeout = timeout
        self.retry_config = RetryConfig(
            max_retries=max_retries,
            backoff_factor=backoff_factor,
            retry_on_status=retry_on_status or (429, 500, 502, 503, 504),
            adaptive=adaptive_rate_limit,
        )
        fill_rate = 1.0 / max(delay, 0.01)
        self.rate_limiter = TokenBucket(capacity=min(5.0, fill_rate * 2), fill_rate=fill_rate)

        if not verify_ssl:
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        with self._config_lock:
            self._settings = {
                "user_agent": user_agent,
                "proxy": proxy,
                "auth_token": auth_token,
                "verify_ssl": verify_ssl,
            }
            self._generation += 1
        with self._cookie_lock:
            self._shared_cookies = requests.cookies.RequestsCookieJar()

        logger.debug(
            "HttpClient configured (delay=%.2fs, timeout=%ds, retries=%d, adaptive=%s)",
            delay, timeout, max_retries, adaptive_rate_limit,
        )
        return self.get_session()

    def set_allowed_origins(self, origins: set[str]) -> None:
        self.allowed_origins = set(origins)

    # -- sessions & cookies --------------------------------------------

    def _build_session(self) -> Session:
        with self._config_lock:
            settings = dict(self._settings)
        session = requests.Session()
        session.headers.update({
            "User-Agent": settings.get("user_agent", SCANNER_UA),
            "Accept": (
                "text/html,application/xhtml+xml,application/xml;q=0.9,"
                "image/avif,image/webp,*/*;q=0.8"
            ),
            "Accept-Language": "en-US,en;q=0.5",
        })
        proxy = settings.get("proxy")
        if proxy:
            session.proxies = {"http": proxy, "https": proxy}
        if settings.get("auth_token"):
            session.headers["Authorization"] = f"Bearer {settings['auth_token']}"
        if not settings.get("verify_ssl", True):
            session.verify = False
        with self._cookie_lock:
            session.cookies.update(self._shared_cookies)
        return session

    def _merge_cookies(self, resp: Response) -> None:
        if not resp.cookies:
            return
        with self._cookie_lock:
            self._shared_cookies.update(resp.cookies)

    def get_session(self) -> Session:
        gen = self._generation
        session = getattr(self._thread_local, "session", None)
        if session is None or getattr(self._thread_local, "generation", None) != gen:
            session = self._build_session()
            self._thread_local.session = session
            self._thread_local.generation = gen
        return session

    # -- SSRF guard -----------------------------------------------------

    def _check_redirect(self, resp: Response) -> None:
        if not self.allowed_origins:
            return
        for historical in resp.history:
            loc = historical.headers.get("Location", "")
            if not loc:
                continue
            parsed = urlparse(loc)
            if not parsed.scheme or not parsed.netloc:
                continue  # relative → same origin
            redirect_origin = f"{parsed.scheme}://{parsed.netloc}"
            redirect_host = parsed.hostname or ""
            if _is_private_ip(redirect_host):
                raise ValueError(
                    f"SSRF blocked: redirect to private IP {redirect_host} "
                    f"(from {historical.url})"
                )
            if redirect_origin not in self.allowed_origins:
                raise ValueError(
                    f"Out-of-scope redirect blocked: {redirect_origin} "
                    f"(from {historical.url})"
                )

    # -- adaptive back-off ---------------------------------------------

    def _apply_adaptive_backoff(self, resp: Response) -> None:
        if not self.retry_config.adaptive:
            return
        if resp.status_code == 429:
            retry_after = resp.headers.get("Retry-After")
            if retry_after:
                try:
                    wait = float(retry_after)
                except ValueError:
                    wait = self.delay * 2
            else:
                wait = self.delay * 2
            with self._adaptive_lock:
                self._adaptive_delay = min(wait, self.retry_config.max_backoff)
                logger.info("Rate limited (429) — adaptive delay set to %.1fs",
                            self._adaptive_delay)
                self.metrics.record_request(success=True, rate_limited=True)
        elif resp.status_code in (503, 502):
            with self._adaptive_lock:
                self._adaptive_delay = min(
                    max(self._adaptive_delay * 1.5, self.delay),
                    self.retry_config.max_backoff,
                )
                logger.info("Server overloaded (%d) — adaptive delay set to %.1fs",
                            resp.status_code, self._adaptive_delay)
        elif resp.status_code < 400:
            with self._adaptive_lock:
                if self._adaptive_delay > 0:
                    self._adaptive_delay = max(0, self._adaptive_delay * 0.8 - 0.1)

    def _get_effective_delay(self) -> float:
        with self._adaptive_lock:
            return self.delay + self._adaptive_delay

    def _pace(self) -> None:
        effective_delay = self._get_effective_delay()
        if self.rate_limiter:
            self.rate_limiter.acquire()
        elif effective_delay > 0:
            time.sleep(effective_delay)

    # -- requests -------------------------------------------------------

    def _request_with_retry(self, method: str, url: str,
                            data: dict | None = None, **kwargs) -> Response:
        kwargs.setdefault("timeout", self.timeout)
        kwargs.setdefault("allow_redirects", True)
        retried = False

        for attempt in range(self.retry_config.max_retries + 1):
            self._pace()
            start_time = time.monotonic()
            try:
                session = self.get_session()
                if method == "GET":
                    resp = session.get(url, **kwargs)
                else:
                    resp = session.post(url, data=data, **kwargs)
                self._merge_cookies(resp)
                elapsed = time.monotonic() - start_time

                if resp.status_code in self.retry_config.retry_on_status:
                    self._apply_adaptive_backoff(resp)
                    if attempt < self.retry_config.max_retries:
                        wait = min(self.retry_config.backoff_factor ** attempt,
                                   self.retry_config.max_backoff)
                        if resp.status_code == 429:
                            retry_after = resp.headers.get("Retry-After")
                            if retry_after:
                                try:
                                    wait = max(wait, float(retry_after))
                                except ValueError:
                                    pass
                        logger.debug("%s %s → %d (attempt %d/%d, retrying in %.1fs)",
                                     method, url, resp.status_code,
                                     attempt + 1, self.retry_config.max_retries + 1, wait)
                        retried = True
                        time.sleep(wait)
                        continue

                self._apply_adaptive_backoff(resp)
                self._check_redirect(resp)
                _enforce_size_limit(resp)
                self.metrics.record_request(
                    success=True, bytes_received=len(resp.content),
                    response_time=elapsed, retried=retried,
                )
                logger.debug("%s %s → %d (%d bytes, %.2fs)",
                             method, url, resp.status_code, len(resp.content), elapsed)
                return resp

            except (requests.ConnectionError, requests.Timeout) as exc:
                elapsed = time.monotonic() - start_time
                if attempt < self.retry_config.max_retries:
                    wait = min(self.retry_config.backoff_factor ** attempt,
                               self.retry_config.max_backoff)
                    logger.debug("%s %s failed (attempt %d/%d): %s — retrying in %.1fs",
                                 method, url, attempt + 1,
                                 self.retry_config.max_retries + 1, exc, wait)
                    retried = True
                    time.sleep(wait)
                    continue
                self.metrics.record_request(success=False, response_time=elapsed, retried=retried)
                logger.warning("%s %s failed after %d attempts: %s",
                               method, url, attempt + 1, exc)
                raise
            except requests.RequestException as exc:
                self.metrics.record_request(
                    success=False, response_time=time.monotonic() - start_time)
                logger.warning("%s %s failed: %s", method, url, exc)
                raise

        self.metrics.record_request(
            success=False, retried=True, response_time=time.monotonic() - start_time)
        return resp  # type: ignore[possibly-undefined]

    def get(self, url: str, **kwargs) -> Response:
        return self._request_with_retry("GET", url, **kwargs)

    def post(self, url: str, data: dict | None = None, **kwargs) -> Response:
        return self._request_with_retry("POST", url, data=data, **kwargs)

    def timed_get(self, url: str, **kwargs) -> tuple[Response, float]:
        self._pace()
        kwargs.setdefault("timeout", max(self.timeout, 35))
        kwargs.setdefault("allow_redirects", True)
        session = self.get_session()
        start = time.monotonic()
        resp = session.get(url, **kwargs)
        elapsed = time.monotonic() - start
        self._merge_cookies(resp)
        self._check_redirect(resp)
        _enforce_size_limit(resp)
        self.metrics.record_request(
            success=True, bytes_received=len(resp.content), response_time=elapsed)
        logger.debug("Timed GET %s → %.2fs", url, elapsed)
        return resp, elapsed

    def timed_post(self, url: str, data: dict | None = None, **kwargs) -> tuple[Response, float]:
        self._pace()
        kwargs.setdefault("timeout", max(self.timeout, 35))
        kwargs.setdefault("allow_redirects", True)
        session = self.get_session()
        start = time.monotonic()
        resp = session.post(url, data=data, **kwargs)
        elapsed = time.monotonic() - start
        self._merge_cookies(resp)
        self._check_redirect(resp)
        _enforce_size_limit(resp)
        self.metrics.record_request(
            success=True, bytes_received=len(resp.content), response_time=elapsed)
        logger.debug("Timed POST %s → %.2fs", url, elapsed)
        return resp, elapsed

    def get_metrics(self) -> dict:
        return self.metrics.snapshot()


# ---------------------------------------------------------------------------
# Current-client resolution (per-scan isolation via ContextVar)
# ---------------------------------------------------------------------------

_default_client = HttpClient()
_current_client: contextvars.ContextVar = contextvars.ContextVar(
    "w3bsp1d3r_http_client", default=None
)


def new_client(**kwargs) -> HttpClient:
    """Create a fresh, isolated HttpClient for a scan."""
    return HttpClient(**kwargs)


def set_current_client(client: Optional[HttpClient]) -> None:
    """Bind `client` as the active client for the current thread/context.
    Call at the start of a scan (orchestrator thread) and inside each worker."""
    _current_client.set(client)


def get_current_client() -> HttpClient:
    """Return the active client (per-scan if set, else the module default)."""
    client = _current_client.get()
    return client if client is not None else _default_client


# ---------------------------------------------------------------------------
# Backwards-compatible module-level API (delegates to the current client)
# ---------------------------------------------------------------------------

def init_session(**kwargs) -> Session:
    """Configure the current client (default client when no scan is active)."""
    return get_current_client().configure(**kwargs)


def set_allowed_origins(origins: set[str]) -> None:
    get_current_client().set_allowed_origins(origins)


def get_session() -> Session:
    return get_current_client().get_session()


def get_metrics() -> dict:
    return get_current_client().get_metrics()


def get(url: str, **kwargs) -> Response:
    """Rate-limited, thread-safe GET with retry, SSRF guard, and size cap."""
    return get_current_client().get(url, **kwargs)


def post(url: str, data: dict | None = None, **kwargs) -> Response:
    """Rate-limited, thread-safe POST with retry, SSRF guard, and size cap."""
    return get_current_client().post(url, data=data, **kwargs)


def timed_get(url: str, **kwargs) -> tuple[Response, float]:
    """GET that also returns elapsed wall-clock time (for time-based blind tests)."""
    return get_current_client().timed_get(url, **kwargs)


def timed_post(url: str, data: dict | None = None, **kwargs) -> tuple[Response, float]:
    """POST that also returns elapsed wall-clock time."""
    return get_current_client().timed_post(url, data=data, **kwargs)


# -- internal helpers preserved for tests / the rate-limit dashboard --------

def _check_redirect(resp: Response) -> None:
    get_current_client()._check_redirect(resp)


def _get_effective_delay() -> float:
    return get_current_client()._get_effective_delay()
