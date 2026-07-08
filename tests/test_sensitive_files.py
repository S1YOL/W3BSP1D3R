"""Tests for sensitive file detection — .env false-negative fix."""
from __future__ import annotations

from unittest.mock import patch, MagicMock

from scanner.testers.sensitive_files import SensitiveFileTester, SensitiveTarget
from scanner.crawler import CrawledPage
from scanner.reporting.models import Severity


def _mock_response(text: str, status_code: int = 200, content_type: str = "text/html"):
    resp = MagicMock()
    resp.text = text
    resp.content = text.encode()
    resp.status_code = status_code
    resp.headers = {"Content-Type": content_type}
    resp.url = "http://target/.env"
    return resp


class TestEnvFileDetection:
    @patch("scanner.testers.sensitive_files.http_utils")
    def test_env_with_confirm_text_html_ct_still_fires(self, mock_http):
        """A .env file with APP_ content must fire even if served as text/html."""
        # Homepage fetch
        homepage_resp = _mock_response("<html>Welcome</html>")
        env_resp = _mock_response(
            "APP_KEY=base64:abc\nAPP_ENV=production\nDB_PASSWORD=secret",
            content_type="text/html",
        )

        call_count = 0
        def side_effect(url, **kwargs):
            nonlocal call_count
            call_count += 1
            if "/.env" in url:
                return env_resp
            return homepage_resp

        mock_http.get = MagicMock(side_effect=side_effect)

        tester = SensitiveFileTester()
        pages = [CrawledPage(url="http://target/", status=200)]
        findings = tester.run(pages)

        env_findings = [f for f in findings if ".env" in f.payload]
        assert len(env_findings) >= 1, "Should detect .env file with APP_ content"

    @patch("scanner.testers.sensitive_files.http_utils")
    def test_dotfile_html_no_confirm_text_does_not_fire(self, mock_http):
        """A dotfile served as HTML WITHOUT matching confirm_text should not fire."""
        homepage_resp = _mock_response("<html>Welcome</html>")
        dotfile_resp = _mock_response(
            "<html>404 page not found</html>",
            content_type="text/html",
        )

        def side_effect(url, **kwargs):
            return homepage_resp if "/.env" not in url else dotfile_resp

        mock_http.get = MagicMock(side_effect=side_effect)

        tester = SensitiveFileTester()
        tester._probe(
            "http://target",
            SensitiveTarget("/.env", Severity.CRITICAL, ".env exposed", "APP_"),
        )
        assert len(tester.findings) == 0, ".env without APP_ in body must not fire"
