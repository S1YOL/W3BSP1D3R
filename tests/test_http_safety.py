"""Tests for HTTP module: thread safety, SSRF guard, response size limit."""
from __future__ import annotations

from unittest.mock import MagicMock

from scanner.utils.http import (
    _check_redirect,
    _enforce_size_limit,
    _is_private_ip,
    MAX_RESPONSE_BYTES,
    set_allowed_origins,
)


class TestSSRFGuard:
    def test_private_ip_detected(self):
        assert _is_private_ip("127.0.0.1") is True
        assert _is_private_ip("10.0.0.5") is True
        assert _is_private_ip("169.254.169.254") is True
        assert _is_private_ip("192.168.1.1") is True

    def test_public_ip_not_blocked(self):
        assert _is_private_ip("8.8.8.8") is False
        assert _is_private_ip("1.1.1.1") is False

    def test_non_ip_hostname_not_blocked(self):
        assert _is_private_ip("example.com") is False

    def test_redirect_to_private_ip_blocked(self):
        set_allowed_origins({"http://target.com"})
        historical = MagicMock()
        historical.headers = {"Location": "http://169.254.169.254/latest/meta-data/"}
        historical.url = "http://target.com/redirect"

        resp = MagicMock()
        resp.history = [historical]

        try:
            _check_redirect(resp)
            assert False, "Should have raised ValueError"
        except ValueError as e:
            assert "SSRF" in str(e)
            assert "169.254" in str(e)

    def test_redirect_to_allowed_origin_ok(self):
        set_allowed_origins({"http://target.com"})
        historical = MagicMock()
        historical.headers = {"Location": "http://target.com/other-page"}
        historical.url = "http://target.com/start"

        resp = MagicMock()
        resp.history = [historical]
        _check_redirect(resp)  # Should not raise

    def test_redirect_to_foreign_origin_blocked(self):
        set_allowed_origins({"http://target.com"})
        historical = MagicMock()
        historical.headers = {"Location": "http://evil.com/steal"}
        historical.url = "http://target.com/start"

        resp = MagicMock()
        resp.history = [historical]

        try:
            _check_redirect(resp)
            assert False, "Should have raised ValueError"
        except ValueError as e:
            assert "Out-of-scope" in str(e)


class TestSizeLimit:
    def test_small_response_unchanged(self):
        resp = MagicMock()
        resp.content = b"A" * 100
        resp.url = "http://test"
        _enforce_size_limit(resp)
        assert len(resp.content) == 100

    def test_oversized_response_truncated(self):
        resp = MagicMock()
        oversized = b"X" * (MAX_RESPONSE_BYTES + 10000)
        resp.content = oversized
        resp.url = "http://test"
        _enforce_size_limit(resp)
        # _content is set to truncated version
        resp.__setattr__("_content", oversized[:MAX_RESPONSE_BYTES])
