from __future__ import annotations
"""
scanner/utils/http.py
----------------------
Shared HTTP session manager with enterprise-grade resilience.

Responsibilities:
  - Maintain a single requests.Session across the entire scan (preserves
    cookies / authentication state automatically)
  - Thread-safe: all session access is protected by a lock
  - Enforce a polite rate-limit between requests
  - SSRF guard: redirect destinations are validated against allowed origins
  - Response size cap (MAX_RESPONSE_BYTES) prevents OOM from malicious targets
  - Set a custom User-Agent so the target can identify scanner traffic in logs
  - Retry with exponential backoff on transient failures
  - Adaptive rate limiting: auto back-off on 429/503 responses
  - Token bucket rate limiter for smooth request distribution
  - Request/response metrics tracking
"""

import ipaddress
import threading
import time
import logging
from typing import Optional
from urllib.parse import urlparse

import requests
from requests import Response, Session

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Per-thread sessions — real HTTP concurrency without a shared-session lock.
#
# requests.Session is not thread-safe, so we give each worker thread its own
# Session (thread-local). Authentication cookies are shared across threads via
# a lock-protected cookie jar: every new thread-local session is seeded from it,
# and Set-Cookie responses are merged back. This lets many requests run truly
# in parallel while preserving authenticated state.
# ---------------------------------------------------------------------------

_thread_local = threading.local()
_session_generation = 0                 # bumped on every init_session()
_config_lock = threading.Lock()         # guards session settings + generation
_cookie_lock = threading.Lock()         # guards the shared cookie jar
_shared_cookies = requests.cookies.RequestsCookieJar()
_session_settings: dict = {}            # template used to build per-thread sessions

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

# Allowed redirect origins — populated by init_session()
_allowed_origins: set[str] = set()

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


metrics = RequestMetrics()


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
            # Sleep for time until next token
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


_retry_config = RetryConfig()
_rate_limiter: Optional[TokenBucket] = None


def _is_private_ip(hostname: str) -> bool:
    """Return True if hostname resolves to or is a private/reserved IP."""
    try:
        addr = ipaddress.ip_address(hostname)
        return any(addr in net for net in _PRIVATE_NETWORKS)
    except ValueError:
        return False


def _check_redirect(resp: Response) -> None:
    """
    Validate that a response's redirect chain stayed within allowed origins.
    Raises ValueError if any redirect went to a disallowed host.

    Relative redirects (no scheme/host) are always allowed — they stay on
    the same origin by definition. Only absolute cross-origin redirects
    and redirects to private IPs are blocked.
    """
    if not _allowed_origins:
        return  # Not yet configured — skip check

    for historical in resp.history:
        loc = historical.headers.get("Location", "")
        if not loc:
            continue
        parsed = urlparse(loc)

        # Relative redirects (no scheme or no host) stay on the same origin
        # by definition — these are always safe to follow
        if not parsed.scheme or not parsed.netloc:
            continue

        redirect_origin = f"{parsed.scheme}://{parsed.netloc}"
        redirect_host = parsed.hostname or ""

        # Block redirects to private/internal IPs (SSRF)
        if _is_private_ip(redirect_host):
            raise ValueError(
                f"SSRF blocked: redirect to private IP {redirect_host} "
                f"(from {historical.url})"
            )

        # Block redirects to origins not in our scope
        if redirect_origin not in _allowed_origins:
            raise ValueError(
                f"Out-of-scope redirect blocked: {redirect_origin} "
                f"(from {historical.url})"
            )


def _enforce_size_limit(resp: Response) -> None:
    """Truncate response content if it exceeds MAX_RESPONSE_BYTES."""
    if len(resp.content) > MAX_RESPONSE_BYTES:
        logger.warning(
            "Response from %s exceeds %d bytes (%d) — truncating",
            resp.url, MAX_RESPONSE_BYTES, len(resp.content),
        )
        # Replace the oversized content with a truncated version
        resp._content = resp.content[:MAX_RESPONSE_BYTES]


def init_session(
    delay: float = DEFAULT_DELAY,
    timeout: int  = DEFAULT_TIMEOUT,
    user_agent: str = SCANNER_UA,
    verify_ssl: bool = True,
    proxy: str | None = None,
    auth_token: str | None = None,
    max_retries: int = 3,
    backoff_factor: float = 2.0,
    adaptive_rate_limit: bool = True,
    retry_on_status: tuple[int, ...] | None = None,
) -> Session:
    """
    Initialise (or re-initialise) the global session.

    Call this once from WebVulnScanner.__init__() before any testers run.

    Args:
        delay               : Seconds to sleep between requests (polite scanning).
        timeout             : Per-request timeout in seconds.
        verify_ssl          : Set False only when testing self-signed certs in labs.
        user_agent          : Custom UA string injected into every request header.
        proxy               : HTTP/SOCKS proxy URL (e.g. http://127.0.0.1:8080 for Burp Suite).
        auth_token          : Bearer/API token for token-based authentication.
        max_retries         : Maximum retry attempts for transient failures.
        backoff_factor      : Multiplier for exponential backoff between retries.
        adaptive_rate_limit : Auto back-off when receiving 429/503 responses.
        retry_on_status     : HTTP status codes that trigger retry.

    Returns:
        The configured requests.Session instance.
    """
    global _delay, _timeout, _retry_config, _rate_limiter
    global _session_generation, _session_settings, _shared_cookies

    _delay   = delay
    _timeout = timeout

    # Configure retry behaviour
    _retry_config = RetryConfig(
        max_retries=max_retries,
        backoff_factor=backoff_factor,
        retry_on_status=retry_on_status or (429, 500, 502, 503, 504),
        adaptive=adaptive_rate_limit,
    )

    # Token bucket: allow burst of 5 requests, then 1/delay per second
    fill_rate = 1.0 / max(delay, 0.01)
    _rate_limiter = TokenBucket(capacity=min(5.0, fill_rate * 2), fill_rate=fill_rate)

    if not verify_ssl:
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    with _config_lock:
        _session_settings = {
            "user_agent": user_agent,
            "proxy": proxy,
            "auth_token": auth_token,
            "verify_ssl": verify_ssl,
        }
        # New generation → existing thread-local sessions are rebuilt on next use.
        _session_generation += 1
    with _cookie_lock:
        _shared_cookies = requests.cookies.RequestsCookieJar()

    logger.debug(
        "HTTP session initialised (delay=%.2fs, timeout=%ds, retries=%d, adaptive=%s)",
        delay, timeout, max_retries, adaptive_rate_limit,
    )
    return get_session()


def _build_session() -> Session:
    """Construct a fresh Session from the current module settings, seeded with
    the shared (e.g. post-authentication) cookies."""
    with _config_lock:
        settings = dict(_session_settings)
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
    # Seed with any shared cookies (auth state established on other threads)
    with _cookie_lock:
        session.cookies.update(_shared_cookies)
    return session


def _merge_cookies(resp: Response) -> None:
    """Merge Set-Cookie values from a response into the shared jar so other
    threads' sessions can pick up newly established (e.g. session) cookies."""
    if not resp.cookies:
        return
    with _cookie_lock:
        _shared_cookies.update(resp.cookies)


def set_allowed_origins(origins: set[str]) -> None:
    """Configure the set of origins that redirects are allowed to reach."""
    global _allowed_origins
    _allowed_origins = origins


def get_session() -> Session:
    """
    Return this thread's Session, creating (or rebuilding) it if needed.

    Each worker thread gets its own Session so requests run truly in parallel.
    A generation counter ensures a session is rebuilt after init_session() is
    called again (e.g. new scan config).
    """
    if not _session_settings:
        # Never initialised — set up sane defaults.
        init_session()
    gen = _session_generation
    session = getattr(_thread_local, "session", None)
    if session is None or getattr(_thread_local, "generation", None) != gen:
        session = _build_session()
        _thread_local.session = session
        _thread_local.generation = gen
    return session


def get_metrics() -> dict:
    """Return a snapshot of request metrics."""
    return metrics.snapshot()


# ---------------------------------------------------------------------------
# Adaptive delay tracking
# ---------------------------------------------------------------------------

_adaptive_delay: float = 0.0  # Additional delay from 429/503 responses
_adaptive_lock = threading.Lock()


def _apply_adaptive_backoff(resp: Response) -> None:
    """Increase delay when receiving rate-limit or server-overload responses."""
    global _adaptive_delay
    if not _retry_config.adaptive:
        return

    if resp.status_code == 429:
        # Check for Retry-After header
        retry_after = resp.headers.get("Retry-After")
        if retry_after:
            try:
                wait = float(retry_after)
            except ValueError:
                wait = _delay * 2
        else:
            wait = _delay * 2

        with _adaptive_lock:
            _adaptive_delay = min(wait, _retry_config.max_backoff)
            logger.info(
                "Rate limited (429) — adaptive delay set to %.1fs",
                _adaptive_delay,
            )
            metrics.record_request(success=True, rate_limited=True)

    elif resp.status_code in (503, 502):
        with _adaptive_lock:
            _adaptive_delay = min(
                max(_adaptive_delay * 1.5, _delay),
                _retry_config.max_backoff,
            )
            logger.info(
                "Server overloaded (%d) — adaptive delay set to %.1fs",
                resp.status_code, _adaptive_delay,
            )

    elif resp.status_code < 400:
        # Successful response — gradually reduce adaptive delay
        with _adaptive_lock:
            if _adaptive_delay > 0:
                _adaptive_delay = max(0, _adaptive_delay * 0.8 - 0.1)


def _get_effective_delay() -> float:
    """Get the current effective delay including adaptive backoff."""
    with _adaptive_lock:
        return _delay + _adaptive_delay


# ---------------------------------------------------------------------------
# Retry wrapper
# ---------------------------------------------------------------------------

def _request_with_retry(
    method: str,
    url: str,
    data: dict | None = None,
    **kwargs,
) -> Response:
    """
    Execute an HTTP request with retry logic and adaptive rate limiting.

    Retries on:
      - Connection errors (ConnectionError, Timeout)
      - Configured status codes (429, 500, 502, 503, 504 by default)

    Uses exponential backoff with jitter between retries.
    """
    kwargs.setdefault("timeout", _timeout)
    kwargs.setdefault("allow_redirects", True)

    last_exc = None
    retried = False

    for attempt in range(_retry_config.max_retries + 1):
        # Rate limiting
        effective_delay = _get_effective_delay()
        if _rate_limiter:
            _rate_limiter.acquire()
        elif effective_delay > 0:
            time.sleep(effective_delay)

        start_time = time.monotonic()
        try:
            session = get_session()
            if method == "GET":
                resp = session.get(url, **kwargs)
            else:
                resp = session.post(url, data=data, **kwargs)
            _merge_cookies(resp)

            elapsed = time.monotonic() - start_time

            # Check if we should retry on this status code
            if resp.status_code in _retry_config.retry_on_status:
                _apply_adaptive_backoff(resp)

                if attempt < _retry_config.max_retries:
                    wait = min(
                        _retry_config.backoff_factor ** attempt,
                        _retry_config.max_backoff,
                    )
                    # Respect Retry-After header for 429
                    if resp.status_code == 429:
                        retry_after = resp.headers.get("Retry-After")
                        if retry_after:
                            try:
                                wait = max(wait, float(retry_after))
                            except ValueError:
                                pass

                    logger.debug(
                        "%s %s → %d (attempt %d/%d, retrying in %.1fs)",
                        method, url, resp.status_code,
                        attempt + 1, _retry_config.max_retries + 1, wait,
                    )
                    retried = True
                    time.sleep(wait)
                    continue

            # Successful or non-retryable response
            _apply_adaptive_backoff(resp)
            _check_redirect(resp)
            _enforce_size_limit(resp)

            metrics.record_request(
                success=True,
                bytes_received=len(resp.content),
                response_time=elapsed,
                retried=retried,
            )

            logger.debug(
                "%s %s → %d (%d bytes, %.2fs)",
                method, url, resp.status_code, len(resp.content), elapsed,
            )
            return resp

        except (requests.ConnectionError, requests.Timeout) as exc:
            last_exc = exc
            elapsed = time.monotonic() - start_time

            if attempt < _retry_config.max_retries:
                wait = min(
                    _retry_config.backoff_factor ** attempt,
                    _retry_config.max_backoff,
                )
                logger.debug(
                    "%s %s failed (attempt %d/%d): %s — retrying in %.1fs",
                    method, url, attempt + 1, _retry_config.max_retries + 1,
                    exc, wait,
                )
                retried = True
                time.sleep(wait)
                continue

            metrics.record_request(
                success=False, response_time=elapsed, retried=retried,
            )
            logger.warning("%s %s failed after %d attempts: %s",
                           method, url, attempt + 1, exc)
            raise

        except requests.RequestException as exc:
            # Non-retryable request error
            metrics.record_request(
                success=False,
                response_time=time.monotonic() - start_time,
            )
            logger.warning("%s %s failed: %s", method, url, exc)
            raise

    # Exhausted retries on bad status code — return last response
    metrics.record_request(
        success=False, retried=True,
        response_time=time.monotonic() - start_time,
    )
    return resp  # type: ignore[possibly-undefined]


# ---------------------------------------------------------------------------
# Public request helpers (backwards-compatible API)
# ---------------------------------------------------------------------------

_delay:   float = DEFAULT_DELAY
_timeout: int   = DEFAULT_TIMEOUT


def get(url: str, **kwargs) -> Response:
    """Rate-limited, thread-safe GET with retry, SSRF guard, and size cap."""
    return _request_with_retry("GET", url, **kwargs)


def post(url: str, data: dict | None = None, **kwargs) -> Response:
    """Rate-limited, thread-safe POST with retry, SSRF guard, and size cap."""
    return _request_with_retry("POST", url, data=data, **kwargs)


def timed_get(url: str, **kwargs) -> tuple[Response, float]:
    """
    GET that also returns the elapsed wall-clock time in seconds.
    Used by the time-based blind SQL injection tester.

    Note: Retries are disabled for timed requests to preserve timing accuracy.
    """
    effective_delay = _get_effective_delay()
    if _rate_limiter:
        _rate_limiter.acquire()
    elif effective_delay > 0:
        time.sleep(effective_delay)

    kwargs.setdefault("timeout", max(_timeout, 35))
    kwargs.setdefault("allow_redirects", True)
    session = get_session()
    start = time.monotonic()
    resp = session.get(url, **kwargs)
    elapsed = time.monotonic() - start
    _merge_cookies(resp)
    _check_redirect(resp)
    _enforce_size_limit(resp)
    metrics.record_request(
        success=True, bytes_received=len(resp.content), response_time=elapsed,
    )
    logger.debug("Timed GET %s → %.2fs", url, elapsed)
    return resp, elapsed


def timed_post(url: str, data: dict | None = None, **kwargs) -> tuple[Response, float]:
    """POST that also returns elapsed wall-clock time.
    Retries disabled to preserve timing accuracy."""
    effective_delay = _get_effective_delay()
    if _rate_limiter:
        _rate_limiter.acquire()
    elif effective_delay > 0:
        time.sleep(effective_delay)

    kwargs.setdefault("timeout", max(_timeout, 35))
    kwargs.setdefault("allow_redirects", True)
    session = get_session()
    start = time.monotonic()
    resp = session.post(url, data=data, **kwargs)
    elapsed = time.monotonic() - start
    _merge_cookies(resp)
    _check_redirect(resp)
    _enforce_size_limit(resp)
    metrics.record_request(
        success=True, bytes_received=len(resp.content), response_time=elapsed,
    )
    logger.debug("Timed POST %s → %.2fs", url, elapsed)
    return resp, elapsed
