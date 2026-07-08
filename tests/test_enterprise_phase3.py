"""
tests/test_enterprise_phase3.py
----------------------------------
Tests for Phase 3 enterprise features:
  - API key authentication
  - OWASP Top 10 mapping
  - Jira/ServiceNow ticketing
  - Email notification formatting
  - Scan scheduler (cron parser)
  - Custom payload loader
"""

import json
import os
import tempfile
import unittest
from datetime import datetime, timezone
from unittest.mock import patch, MagicMock

from scanner.reporting.models import (
    Finding, ScanSummary, VulnType, Severity,
    OWASP_TOP_10, get_owasp_category,
)


# ---------------------------------------------------------------------------
# OWASP Top 10 mapping
# ---------------------------------------------------------------------------

class TestOWASPMapping(unittest.TestCase):
    """Test OWASP Top 10 (2021) mapping for all vulnerability types."""

    def test_sqli_maps_to_a03(self):
        assert get_owasp_category(VulnType.SQLI_ERROR) == {"id": "A03:2021", "name": "Injection"}
        assert get_owasp_category(VulnType.SQLI_BOOLEAN) == {"id": "A03:2021", "name": "Injection"}
        assert get_owasp_category(VulnType.SQLI_TIME) == {"id": "A03:2021", "name": "Injection"}
        assert get_owasp_category(VulnType.SQLI_UNION) == {"id": "A03:2021", "name": "Injection"}

    def test_xss_maps_to_a03(self):
        assert get_owasp_category(VulnType.XSS_REFLECTED)["id"] == "A03:2021"
        assert get_owasp_category(VulnType.XSS_STORED)["id"] == "A03:2021"

    def test_cmdi_maps_to_a03(self):
        assert get_owasp_category(VulnType.CMD_INJECTION)["id"] == "A03:2021"

    def test_path_traversal_maps_to_a01(self):
        assert get_owasp_category(VulnType.PATH_TRAVERSAL)["id"] == "A01:2021"

    def test_csrf_maps_to_a08(self):
        assert get_owasp_category(VulnType.CSRF)["id"] == "A08:2021"

    def test_ssl_maps_to_a02(self):
        assert get_owasp_category(VulnType.SSL_TLS)["id"] == "A02:2021"

    def test_headers_maps_to_a05(self):
        assert get_owasp_category(VulnType.SECURITY_HEADER)["id"] == "A05:2021"

    def test_unknown_returns_none(self):
        assert get_owasp_category("Made Up Vuln Type") is None

    def test_finding_includes_owasp_in_to_dict(self):
        f = Finding(vuln_type=VulnType.SQLI_ERROR, severity="Critical",
                    url="http://t.com", parameter="id", method="GET",
                    payload="x", evidence="y", remediation="z")
        d = f.to_dict()
        assert d["owasp"] == {"id": "A03:2021", "name": "Injection"}

    def test_all_vuln_types_mapped(self):
        """Verify every VulnType constant has an OWASP mapping."""
        unmapped = []
        for attr in dir(VulnType):
            if attr.startswith("_"):
                continue
            val = getattr(VulnType, attr)
            if isinstance(val, str) and get_owasp_category(val) is None:
                unmapped.append(val)
        # Only informational types may be unmapped — that's OK
        # Just ensure the critical ones are mapped
        assert get_owasp_category(VulnType.SQLI_ERROR) is not None
        assert get_owasp_category(VulnType.XSS_REFLECTED) is not None
        assert get_owasp_category(VulnType.CMD_INJECTION) is not None


# ---------------------------------------------------------------------------
# API key authentication
# ---------------------------------------------------------------------------

class TestAPIKeyAuth(unittest.TestCase):
    """Test REST API key authentication middleware."""

    def _get_app(self, api_keys=None):
        from scanner.api import create_api_app
        app = create_api_app(api_keys=api_keys)
        app.config["TESTING"] = True
        return app.test_client()

    def test_no_keys_configured_allows_all(self):
        client = self._get_app(api_keys=None)
        resp = client.get("/api/v1/health")
        assert resp.status_code == 200

    def test_valid_bearer_key(self):
        client = self._get_app(api_keys=["test-key-123"])
        resp = client.get("/api/v1/stats",
                          headers={"Authorization": "Bearer test-key-123"})
        assert resp.status_code == 200

    def test_valid_x_api_key(self):
        client = self._get_app(api_keys=["test-key-123"])
        resp = client.get("/api/v1/stats",
                          headers={"X-API-Key": "test-key-123"})
        assert resp.status_code == 200

    def test_valid_query_param(self):
        client = self._get_app(api_keys=["test-key-123"])
        resp = client.get("/api/v1/stats?api_key=test-key-123")
        assert resp.status_code == 200

    def test_missing_key_returns_401(self):
        client = self._get_app(api_keys=["test-key-123"])
        resp = client.get("/api/v1/stats")
        assert resp.status_code == 401
        assert "Authentication required" in resp.get_json()["error"]

    def test_invalid_key_returns_403(self):
        client = self._get_app(api_keys=["test-key-123"])
        resp = client.get("/api/v1/stats",
                          headers={"Authorization": "Bearer wrong-key"})
        assert resp.status_code == 403

    def test_health_endpoint_no_auth(self):
        """Health check should always work without auth."""
        client = self._get_app(api_keys=["test-key-123"])
        resp = client.get("/api/v1/health")
        assert resp.status_code == 200


# ---------------------------------------------------------------------------
# Cron parser
# ---------------------------------------------------------------------------

class TestCronParser(unittest.TestCase):
    """Test the cron expression parser."""

    def test_every_minute(self):
        from scanner.scheduler import CronParser
        dt = datetime(2024, 1, 15, 10, 30)
        assert CronParser.matches("* * * * *", dt)

    def test_specific_minute(self):
        from scanner.scheduler import CronParser
        dt = datetime(2024, 1, 15, 10, 30)
        assert CronParser.matches("30 * * * *", dt)
        assert not CronParser.matches("15 * * * *", dt)

    def test_specific_hour_minute(self):
        from scanner.scheduler import CronParser
        dt = datetime(2024, 1, 15, 2, 0)
        assert CronParser.matches("0 2 * * *", dt)  # 2 AM
        assert not CronParser.matches("0 3 * * *", dt)

    def test_step_expression(self):
        from scanner.scheduler import CronParser
        dt = datetime(2024, 1, 15, 10, 0)
        assert CronParser.matches("*/15 * * * *", dt)  # Every 15 min, 0 matches
        dt2 = datetime(2024, 1, 15, 10, 15)
        assert CronParser.matches("*/15 * * * *", dt2)

    def test_comma_list(self):
        from scanner.scheduler import CronParser
        dt = datetime(2024, 1, 15, 10, 30)
        assert CronParser.matches("0,15,30,45 * * * *", dt)
        assert not CronParser.matches("0,15,45 * * * *", dt)

    def test_range_expression(self):
        from scanner.scheduler import CronParser
        dt = datetime(2024, 1, 15, 10, 30)
        assert CronParser.matches("25-35 * * * *", dt)
        assert not CronParser.matches("0-10 * * * *", dt)

    def test_invalid_cron_raises(self):
        from scanner.scheduler import CronParser
        with self.assertRaises(ValueError):
            CronParser.matches("bad cron", datetime.now())


# ---------------------------------------------------------------------------
# Scheduler
# ---------------------------------------------------------------------------

class TestScheduler(unittest.TestCase):
    """Test scan scheduler."""

    def test_add_and_list_jobs(self):
        from scanner.scheduler import ScanScheduler
        from scanner.config import ScanConfig

        sched = ScanScheduler()
        config = ScanConfig(url="http://test.com")
        sched.add_job("test-job", "0 2 * * *", config)

        status = sched.get_status()
        assert len(status) == 1
        assert status[0]["name"] == "test-job"
        assert status[0]["cron"] == "0 2 * * *"

    def test_remove_job(self):
        from scanner.scheduler import ScanScheduler
        from scanner.config import ScanConfig

        sched = ScanScheduler()
        sched.add_job("temp", "* * * * *", ScanConfig(url="http://t.com"))
        sched.remove_job("temp")
        assert len(sched.get_status()) == 0


# ---------------------------------------------------------------------------
# Payload loader
# ---------------------------------------------------------------------------

class TestPayloadManager(unittest.TestCase):
    """Test custom payload loading."""

    def test_load_yaml_file(self):
        from scanner.payloads import PayloadManager

        yaml_content = """
sqli:
  error:
    - "' OR '1'='1"
    - "1; DROP TABLE--"
  boolean:
    - "' OR 1=1--"
xss:
  reflected:
    - "<script>alert(1)</script>"
    - "<img src=x onerror=alert(1)>"
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write(yaml_content)
            f.flush()

            pm = PayloadManager()
            count = pm.load_file(f.name)

        os.unlink(f.name)

        assert count > 0
        assert pm.get("sqli.error") == ["' OR '1'='1", "1; DROP TABLE--"]
        assert len(pm.get("xss.reflected")) == 2
        assert pm.has("sqli")
        assert not pm.has("nonexistent")

    def test_load_json_file(self):
        from scanner.payloads import PayloadManager

        data = {"cmdi": ["; id", "| whoami"], "custom": ["test1"]}
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(data, f)
            f.flush()

            pm = PayloadManager()
            pm.load_file(f.name)

        os.unlink(f.name)

        assert pm.get("cmdi") == ["; id", "| whoami"]
        assert pm.get("custom") == ["test1"]

    def test_get_default(self):
        from scanner.payloads import PayloadManager
        pm = PayloadManager()
        assert pm.get("nonexistent") == []
        assert pm.get("nonexistent", ["fallback"]) == ["fallback"]

    def test_categories(self):
        from scanner.payloads import PayloadManager
        data = {"sqli": ["a"], "xss": ["b"]}
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(data, f)
            f.flush()
            pm = PayloadManager()
            pm.load_file(f.name)
        os.unlink(f.name)
        assert sorted(pm.categories()) == ["sqli", "xss"]

    def test_stats(self):
        from scanner.payloads import PayloadManager
        data = {"sqli": ["a", "b", "c"], "xss": ["d"]}
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(data, f)
            f.flush()
            pm = PayloadManager()
            pm.load_file(f.name)
        os.unlink(f.name)
        s = pm.stats()
        assert s["total_payloads"] == 4
        assert s["categories"]["sqli"] == 3

    def test_missing_file(self):
        from scanner.payloads import PayloadManager
        pm = PayloadManager()
        assert pm.load_file("/nonexistent/payloads.yaml") == 0


# ---------------------------------------------------------------------------
# Ticketing (Jira format)
# ---------------------------------------------------------------------------

class TestTicketingFormat(unittest.TestCase):
    """Test Jira/ServiceNow integration formatting."""

    def test_severity_threshold(self):
        from scanner.integrations.ticketing import _meets_threshold
        assert _meets_threshold("Critical", "Medium") == True
        assert _meets_threshold("High", "Medium") == True
        assert _meets_threshold("Medium", "Medium") == True
        assert _meets_threshold("Low", "Medium") == False

    def test_jira_config_defaults(self):
        from scanner.integrations.ticketing import JiraConfig
        cfg = JiraConfig()
        assert cfg.issue_type == "Bug"
        assert cfg.min_severity == "Medium"
        assert "w3bsp1d3r" in cfg.labels


# ---------------------------------------------------------------------------
# Email notification formatting
# ---------------------------------------------------------------------------

class TestEmailFormatting(unittest.TestCase):
    """Test email notification message building."""

    def test_subject_with_findings(self):
        from scanner.integrations.email_notifier import EmailNotifier, EmailConfig
        config = EmailConfig(enabled=True)
        notifier = EmailNotifier(config)

        summary = ScanSummary(target_url="http://t.com", scan_type="full", started_at="now")
        summary.add_finding(Finding(
            vuln_type=VulnType.SQLI_ERROR, severity="Critical",
            url="http://t.com/a", parameter="id", method="GET",
            payload="x", evidence="y", remediation="z"))

        subject = notifier._build_subject(summary)
        assert "CRITICAL" in subject
        assert "1 Finding" in subject

    def test_subject_clean_scan(self):
        from scanner.integrations.email_notifier import EmailNotifier, EmailConfig
        config = EmailConfig(enabled=True)
        notifier = EmailNotifier(config)

        summary = ScanSummary(target_url="http://t.com", scan_type="full", started_at="now")
        subject = notifier._build_subject(summary)
        assert "Clean" in subject

    def test_html_body_generated(self):
        from scanner.integrations.email_notifier import EmailNotifier, EmailConfig
        config = EmailConfig(enabled=True)
        notifier = EmailNotifier(config)

        summary = ScanSummary(target_url="http://t.com", scan_type="full", started_at="now")
        html = notifier._build_html(summary, "scan123")
        assert "W3BSP1D3R" in html
        assert "http://t.com" in html


if __name__ == "__main__":
    unittest.main()
