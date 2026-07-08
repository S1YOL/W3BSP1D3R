from __future__ import annotations
"""
scanner/testers/dom_xss.py
---------------------------
DOM-based Cross-Site Scripting tester (browser-driven).

Security concept (OWASP A03:2021 — Injection / DOM XSS):
  DOM-based XSS occurs entirely in the browser: client-side JavaScript reads
  attacker-controllable input from a *source* (location.hash, location.search,
  document.referrer, postMessage, …) and writes it to a dangerous *sink*
  (innerHTML, document.write, eval, setAttribute on an event handler, …)
  WITHOUT sanitisation. The malicious payload never appears in the server
  response, so server-side reflected-XSS checks miss it entirely.

Detection approach:
  Unlike the reflected/stored XSS testers (which grep the HTML response), DOM
  XSS can only be confirmed by executing JavaScript. We render each candidate
  URL in a headless browser and inject a payload that calls alert(marker):

    * URL fragment:   https://app/#<img src=x onerror=alert(MARKER)>
                      (the fragment is never sent to the server — a pure
                       client-side sink is the only way this can fire)
    * Query params:   https://app/?q=<svg onload=alert(MARKER)>

  A dialog handler captures any alert()/confirm()/prompt(). If a dialog fires
  carrying our unique marker, script execution is *proven* — a Certain finding.

This tester is a no-op when Playwright is not installed.
"""

import logging
import secrets

from scanner.crawler import CrawledPage
from scanner.reporting.models import Confidence, Finding, Severity, VulnType
from scanner.testers.base import BaseTester
from scanner.utils.display import print_status

logger = logging.getLogger(__name__)

# Payloads that execute automatically on navigation (no user interaction).
_PAYLOADS = [
    "<img src=x onerror=alert('{m}')>",
    "<svg onload=alert('{m}')>",
    "\"><img src=x onerror=alert('{m}')>",
    "'><svg onload=alert('{m}')>",
]

# Keep browser work bounded — DOM XSS testing is slow (one navigation per probe).
_MAX_TARGETS = 40

_REMEDIATION = (
    "Treat all client-side input sources (location.hash, location.search, "
    "document.referrer, postMessage data, URL parameters) as untrusted. Never "
    "pass them to dangerous sinks such as innerHTML, outerHTML, document.write, "
    "insertAdjacentHTML, eval, setTimeout(string), or on* attribute assignment. "
    "Use textContent / setAttribute for data, and sanitise rich text with a "
    "vetted library (e.g. DOMPurify). Enforce a strict Content-Security-Policy. "
    "Ref: OWASP DOM-based XSS Prevention Cheat Sheet."
)


class DOMXSSTester(BaseTester):
    """Detects DOM-based XSS by executing payloads in a real headless browser."""

    def __init__(self) -> None:
        super().__init__(name="DOM-based XSS Tester")

    def run(self, pages: list[CrawledPage]) -> list[Finding]:
        self.findings.clear()
        self._params_tested = 0

        from scanner.utils import renderer as rmod
        if not rmod.is_available():
            logger.info(
                "DOM XSS tester skipped — Playwright not installed "
                "(pip install playwright && playwright install chromium)"
            )
            return self.findings

        # Build a bounded, de-duplicated target list of (url, [param names]).
        targets: list[tuple[str, list[str]]] = []
        seen: set[str] = set()
        for page in pages:
            base = page.url.split("#")[0]
            if base in seen:
                continue
            seen.add(base)
            targets.append((base, list(page.get_params.keys())))
            if len(targets) >= _MAX_TARGETS:
                break

        try:
            with rmod.BrowserRenderer(timeout=15000, block_resources=True) as browser:
                for url, params in targets:
                    print_status(f"DOM-XSS → {url}")
                    # The URL fragment is a pure client-side source — always test it.
                    self._test_target(browser, url, param=None)
                    for param in params:
                        self._test_target(browser, url, param=param)
        except Exception as exc:  # browser launch/teardown issues shouldn't crash the scan
            logger.warning("DOM XSS tester error: %s", exc)

        return self.findings

    # ------------------------------------------------------------------
    # Probe a single (url, param|fragment) with each payload until one fires.
    # ------------------------------------------------------------------

    def _test_target(self, browser, url: str, param: str | None) -> None:
        self._count_test()
        for template in _PAYLOADS:
            marker = "DOMXSS" + secrets.token_hex(3).upper()
            payload = template.format(m=marker)

            if param is None:
                test_url = f"{url}#{payload}"
                location = "#fragment"
                sink_hint = (
                    "URL fragment executed in the browser — a client-side sink "
                    "(e.g. location.hash → innerHTML) rendered attacker input as HTML."
                )
            else:
                test_url = self._inject_get_param(url, param, payload)
                location = param
                sink_hint = (
                    f"parameter '{param}' executed in the browser — client-side "
                    f"JavaScript passed it to a dangerous sink without sanitisation."
                )

            if self._execute_and_detect(browser, test_url, marker):
                self._log_finding(Finding(
                    vuln_type=VulnType.XSS_DOM,
                    severity=Severity.HIGH,
                    url=url,
                    parameter=location,
                    method="GET",
                    payload=payload,
                    evidence=(
                        f"alert('{marker}') fired in-browser: the injected payload in the "
                        f"{sink_hint}"
                    ),
                    remediation=_REMEDIATION,
                    confidence=Confidence.CERTAIN,
                    extra={"marker": marker, "source": location},
                ))
                return  # one confirmed finding per target is enough

    def _execute_and_detect(self, browser, test_url: str, marker: str) -> bool:
        """Navigate to `test_url` and return True if a dialog carrying `marker` fires."""
        fired: list[str] = []
        page = browser.new_page_with_dialog_capture(fired)
        try:
            page.goto(test_url, wait_until="networkidle", timeout=15000)
            # Some sinks fire on a microtask/timer after load.
            page.wait_for_timeout(400)
        except Exception as exc:
            logger.debug("DOM XSS navigation failed for %s: %s", test_url, exc)
        finally:
            try:
                page.close()
            except Exception:
                pass
        return any(marker in msg for msg in fired)
