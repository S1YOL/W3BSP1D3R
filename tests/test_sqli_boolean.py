"""Tests for boolean-based blind SQLi 3-way + recheck logic."""
from __future__ import annotations

from unittest.mock import patch, MagicMock

from scanner.testers.sqli import SQLiTester
from scanner.crawler import CrawledForm, FormField


def _make_form(action: str = "http://target/vuln", method: str = "POST") -> CrawledForm:
    return CrawledForm(
        page_url="http://target/page",
        action_url=action,
        method=method,
        fields=[FormField(name="q", field_type="text", value="")],
    )


def _mock_response(text: str, status_code: int = 200):
    resp = MagicMock()
    resp.text = text
    resp.content = text.encode()
    resp.status_code = status_code
    resp.headers = {}
    resp.url = "http://target/vuln"
    return resp


class TestBooleanSQLiForm:
    """Verify 3-way baseline + recheck gates in _boolean_based_form."""

    @patch("scanner.testers.sqli.http_utils")
    def test_true_matches_baseline_false_differs_fires(self, mock_http):
        """TRUE ≈ baseline AND FALSE ≠ both → should fire."""
        baseline_text = "A" * 500
        true_text = "A" * 505          # within 10% of baseline
        false_text = "B" * 100         # dramatically different
        recheck_text = "A" * 507       # consistent with TRUE (drift < 5%)

        call_count = 0
        def side_effect(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return _mock_response(true_text)
            elif call_count == 2:
                return _mock_response(false_text)
            else:
                return _mock_response(recheck_text)

        mock_http.post = MagicMock(side_effect=side_effect)
        mock_http.get = MagicMock(side_effect=side_effect)

        tester = SQLiTester()
        tester.findings.clear()
        form = _make_form()
        result = tester._boolean_based_form(form, "q", baseline_text)

        assert result is True
        assert len(tester.findings) == 1
        assert "3-way + recheck" in tester.findings[0].evidence

    @patch("scanner.testers.sqli.http_utils")
    def test_true_diverges_from_baseline_no_fire(self, mock_http):
        """TRUE diverges >10% from baseline → should NOT fire (dynamic page)."""
        baseline_text = "A" * 500
        true_text = "A" * 200          # 60% different from baseline
        false_text = "B" * 100

        call_count = 0
        def side_effect(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count % 2 == 1:
                return _mock_response(true_text)
            else:
                return _mock_response(false_text)

        mock_http.post = MagicMock(side_effect=side_effect)

        tester = SQLiTester()
        tester.findings.clear()
        form = _make_form()
        result = tester._boolean_based_form(form, "q", baseline_text)

        assert result is False
        assert len(tester.findings) == 0

    @patch("scanner.testers.sqli.http_utils")
    def test_recheck_inconsistent_no_fire(self, mock_http):
        """TRUE matches baseline, FALSE differs, but recheck is inconsistent → no fire."""
        baseline_text = "A" * 500
        true_text = "A" * 505
        false_text = "B" * 100
        recheck_text = "C" * 200       # >5% drift from TRUE → inconsistent

        call_count = 0
        def side_effect(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return _mock_response(true_text)
            elif call_count == 2:
                return _mock_response(false_text)
            else:
                return _mock_response(recheck_text)

        mock_http.post = MagicMock(side_effect=side_effect)

        tester = SQLiTester()
        tester.findings.clear()
        form = _make_form()
        result = tester._boolean_based_form(form, "q", baseline_text)

        assert result is False
        assert len(tester.findings) == 0

    @patch("scanner.testers.sqli.http_utils")
    def test_small_diff_no_fire(self, mock_http):
        """TRUE ≈ baseline but FALSE is only slightly different → no fire."""
        baseline_text = "A" * 500
        true_text = "A" * 505
        false_text = "A" * 490         # diff=15, pct=~3% — below thresholds

        call_count = 0
        def side_effect(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count % 2 == 1:
                return _mock_response(true_text)
            else:
                return _mock_response(false_text)

        mock_http.post = MagicMock(side_effect=side_effect)

        tester = SQLiTester()
        tester.findings.clear()
        form = _make_form()
        result = tester._boolean_based_form(form, "q", baseline_text)

        assert result is False
        assert len(tester.findings) == 0
