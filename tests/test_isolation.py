from __future__ import annotations
"""
tests/test_isolation.py
------------------------
Phase B — per-scan isolation. Proves two scans running at the same time (e.g.
via the REST API) do NOT share HTTP session, SSRF scope, rate limiter, or
metrics, so they cannot corrupt each other's results.
"""

import threading
import time
import unittest
import urllib.request

from scanner.utils import http
from scanner.testers import base as tbase


class TestClientContextIsolation(unittest.TestCase):
    """Deterministic proof that the current-client ContextVar isolates threads."""

    def test_two_threads_see_their_own_client(self):
        ca = http.new_client(delay=0)
        ca.set_allowed_origins({"http://a.example"})
        cb = http.new_client(delay=0)
        cb.set_allowed_origins({"http://b.example"})

        seen: dict[str, set] = {}
        barrier = threading.Barrier(2)

        def worker(name, client):
            http.set_current_client(client)
            barrier.wait()  # both threads have bound their client before reading
            seen[name] = http.get_current_client().allowed_origins

        t1 = threading.Thread(target=worker, args=("a", ca))
        t2 = threading.Thread(target=worker, args=("b", cb))
        t1.start(); t2.start(); t1.join(); t2.join()

        self.assertEqual(seen["a"], {"http://a.example"})
        self.assertEqual(seen["b"], {"http://b.example"})

    def test_scope_contextvar_isolation(self):
        seen: dict[str, tuple] = {}
        barrier = threading.Barrier(2)

        def worker(name, include):
            tbase.set_scope_patterns(include, [])
            barrier.wait()
            seen[name] = tbase.get_scope_patterns()

        t1 = threading.Thread(target=worker, args=("a", ["*/a/*"]))
        t2 = threading.Thread(target=worker, args=("b", ["*/b/*"]))
        t1.start(); t2.start(); t1.join(); t2.join()

        self.assertEqual(seen["a"][0], ["*/a/*"])
        self.assertEqual(seen["b"][0], ["*/b/*"])


class TestConcurrentScansIsolated(unittest.TestCase):
    """End-to-end: two concurrent full scans of different targets stay separate."""

    def test_concurrent_scans_do_not_cross_contaminate(self):
        from scanner.config import ScanConfig
        from scanner.core import WebVulnScanner
        from tests.vulnerable_app import VulnerableApp

        with VulnerableApp() as app1, VulnerableApp() as app2:
            for app in (app1, app2):
                for _ in range(40):
                    try:
                        urllib.request.urlopen(app.url, timeout=1).read()
                        break
                    except Exception:
                        time.sleep(0.1)

            results: dict[str, object] = {}
            errors: dict[str, Exception] = {}

            def run(name, url):
                try:
                    cfg = ScanConfig(url=url, scan_type="full", threads=4,
                                     max_pages=15, delay=0)
                    cfg.output_formats = []  # don't write report files in tests
                    results[name] = WebVulnScanner(url=url, config=cfg).scan()
                except Exception as exc:  # noqa
                    errors[name] = exc

            t1 = threading.Thread(target=run, args=("a", app1.url))
            t2 = threading.Thread(target=run, args=("b", app2.url))
            t1.start(); t2.start(); t1.join(); t2.join()

            self.assertEqual(errors, {}, f"scan errors: {errors}")

            host1 = app1.url.split("://")[1]
            host2 = app2.url.split("://")[1]

            summ_a = results["a"]
            summ_b = results["b"]

            # Each summary targets its own app.
            self.assertEqual(summ_a.target_url, app1.url)
            self.assertEqual(summ_b.target_url, app2.url)

            # No finding in scan A references app B's origin, and vice versa —
            # the definitive proof that sessions/scope didn't leak between scans.
            for f in summ_a.findings:
                self.assertNotIn(host2, f.url,
                                 f"scan A leaked a finding for app B: {f.url}")
            for f in summ_b.findings:
                self.assertNotIn(host1, f.url,
                                 f"scan B leaked a finding for app A: {f.url}")

            # Both actually found the planted SQLi (each on its own host).
            self.assertTrue(any("sqli" in f.url and host1 in f.url for f in summ_a.findings))
            self.assertTrue(any("sqli" in f.url and host2 in f.url for f in summ_b.findings))


if __name__ == "__main__":
    unittest.main()
