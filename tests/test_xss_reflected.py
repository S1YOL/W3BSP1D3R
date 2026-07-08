"""Tests for XSS structural payload verification (_is_reflected)."""
from __future__ import annotations

from scanner.testers.xss import XSSTester


class TestIsReflected:
    """Verify that _is_reflected requires structural elements, not just marker."""

    def test_script_tag_unencoded_fires(self):
        marker = "XSSTESTAAAA1234"
        payload = f"<script>alert('{marker}')</script>"
        response = f"<html><body><script>alert('{marker}')</script></body></html>"
        assert XSSTester._is_reflected(marker, response, payload) is True

    def test_marker_present_but_html_encoded_no_fire(self):
        """App reflects the marker but encodes <script> → &lt;script&gt;."""
        marker = "XSSTESTBBBB5678"
        payload = f"<script>alert('{marker}')</script>"
        response = f"<html><body>&lt;script&gt;alert('{marker}')&lt;/script&gt;</body></html>"
        assert XSSTester._is_reflected(marker, response, payload) is False

    def test_event_handler_unencoded_fires(self):
        marker = "XSSTESTCCCC9012"
        payload = f"<img src=x onerror=alert('{marker}')>"
        response = f'<html><body><img src=x onerror=alert(\'{marker}\')></body></html>'
        assert XSSTester._is_reflected(marker, response, payload) is True

    def test_event_handler_encoded_no_fire(self):
        marker = "XSSTESTDDDD3456"
        payload = f"<img src=x onerror=alert('{marker}')>"
        response = f"<html><body>&lt;img src=x onerror=alert('{marker}')&gt;</body></html>"
        assert XSSTester._is_reflected(marker, response, payload) is False

    def test_svg_onload_fires(self):
        marker = "XSSTESTEEEE7890"
        payload = f"'><svg onload=alert('{marker}')>"
        response = f"""<html><body><input value=''><svg onload=alert('{marker}')></body></html>"""
        assert XSSTester._is_reflected(marker, response, payload) is True

    def test_marker_absent_no_fire(self):
        marker = "XSSTESTFFFF0000"
        payload = f"<script>alert('{marker}')</script>"
        response = "<html><body>Nothing here</body></html>"
        assert XSSTester._is_reflected(marker, response, payload) is False

    def test_legacy_no_payload_marker_only(self):
        """Without payload arg, falls back to marker-only check (backward compat)."""
        marker = "XSSTESTGGGG1111"
        response = f"<html>Your search: {marker}</html>"
        assert XSSTester._is_reflected(marker, response) is True

    def test_javascript_protocol_fires(self):
        marker = "XSSTESTHHHH2222"
        payload = f"javascript:alert('{marker}')"
        response = f'<a href="javascript:alert(\'{marker}\')">click</a>'
        assert XSSTester._is_reflected(marker, response, payload) is True

    def test_attribute_breakout_fires(self):
        marker = "XSSTEST1111AAAA"
        payload = f'"><script>alert("{marker}")</script>'
        response = f'<input value=""><script>alert("{marker}")</script>">'
        assert XSSTester._is_reflected(marker, response, payload) is True
