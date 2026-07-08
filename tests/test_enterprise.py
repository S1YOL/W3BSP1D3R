"""
tests/test_enterprise.py
--------------------------
Unit tests for all enterprise modules added in v3.0.0-beta.

Covers:
  - Config loading, env var expansion, profiles, policy enforcement
  - Structured JSON logging
  - Checkpoint save/load/clear
  - Audit logging
  - Finding deduplication and fingerprints
  - Scope filtering (include/exclude patterns)
  - Retry logic and token bucket rate limiter
  - Request metrics
  - Scan diff/comparison
  - Webhook message formatting
  - Database operations
"""

import json
import os
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

# ---------------------------------------------------------------------------
# Config tests
# ---------------------------------------------------------------------------

class TestConfigEnvExpansion(unittest.TestCase):
    """Test environment variable expansion in config values."""

    def test_expand_simple_var(self):
        from scanner.config import _expand_env_vars
        with patch.dict(os.environ, {"MY_KEY": "secret123"}):
            assert _expand_env_vars("${MY_KEY}") == "secret123"

    def test_expand_with_default(self):
        from scanner.config import _expand_env_vars
        # Variable not set — use default
        result = _expand_env_vars("${NONEXISTENT_VAR:-fallback}")
        assert result == "fallback"

    def test_expand_nested_dict(self):
        from scanner.config import _expand_env_vars
        with patch.dict(os.environ, {"API_KEY": "abc"}):
            data = {"integrations": {"vt": {"key": "${API_KEY}"}}}
            result = _expand_env_vars(data)
            assert result["integrations"]["vt"]["key"] == "abc"

    def test_expand_list(self):
        from scanner.config import _expand_env_vars
        with patch.dict(os.environ, {"HOST": "example.com"}):
            result = _expand_env_vars(["${HOST}", "static"])
            assert result == ["example.com", "static"]

    def test_non_string_passthrough(self):
        from scanner.config import _expand_env_vars
        assert _expand_env_vars(42) == 42
        assert _expand_env_vars(True) is True


class TestConfigProfiles(unittest.TestCase):
    """Test scan profile application."""

    def test_quick_profile(self):
        from scanner.config import ScanConfig, _apply_profile
        config = ScanConfig()
        _apply_profile(config, "quick")
        assert config.threads == 2
        assert config.max_pages == 10
        assert config.delay == 0.2

    def test_thorough_profile(self):
        from scanner.config import ScanConfig, _apply_profile
        config = ScanConfig()
        _apply_profile(config, "thorough")
        assert config.threads == 8
        assert config.max_pages == 500
        assert config.delay == 1.0

    def test_stealth_profile(self):
        from scanner.config import ScanConfig, _apply_profile
        config = ScanConfig()
        _apply_profile(config, "stealth")
        assert config.threads == 1
        assert config.delay == 3.0

    def test_unknown_profile_raises(self):
        from scanner.config import ScanConfig, _apply_profile
        config = ScanConfig()
        with self.assertRaises(ValueError):
            _apply_profile(config, "nonexistent")

    def test_available_profiles(self):
        from scanner.config import get_available_profiles
        profiles = get_available_profiles()
        assert "quick" in profiles
        assert "standard" in profiles
        assert "thorough" in profiles
        assert "stealth" in profiles


class TestConfigPolicies(unittest.TestCase):
    """Test policy enforcement."""

    def test_min_delay_enforced(self):
        from scanner.config import ScanConfig
        config = ScanConfig(delay=0.1)
        config.policy.min_delay = 1.0
        warnings = config.apply_policies()
        assert config.delay == 1.0
        assert len(warnings) == 1

    def test_max_threads_enforced(self):
        from scanner.config import ScanConfig
        config = ScanConfig(threads=64)
        config.policy.max_threads = 8
        warnings = config.apply_policies()
        assert config.threads == 8
        assert len(warnings) == 1

    def test_fail_on_policy(self):
        from scanner.config import ScanConfig
        config = ScanConfig()
        config.policy.fail_on = "high"
        config.apply_policies()
        assert config.fail_on == "high"


class TestConfigYAMLLoading(unittest.TestCase):
    """Test YAML config file loading."""

    def test_load_yaml_config(self):
        from scanner.config import load_config

        yaml_content = """
profile: quick
url: http://test.com
scan_type: xss
output:
  base_filename: my_report
  formats: [html, json]
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write(yaml_content)
            f.flush()
            config = load_config(f.name)

        os.unlink(f.name)

        assert config.url == "http://test.com"
        assert config.scan_type == "xss"
        assert config.output == "my_report"
        assert config.threads == 2  # from quick profile
        assert "html" in config.output_formats

    def test_missing_file_raises(self):
        from scanner.config import load_config
        with self.assertRaises(FileNotFoundError):
            load_config("/nonexistent/config.yaml")


class TestConfigEnvVarLoading(unittest.TestCase):
    """Test loading config from environment variables."""

    def test_env_vars_loaded(self):
        from scanner.config import load_config_from_env
        with patch.dict(os.environ, {
            "W3BSP1D3R_URL": "http://env-target.com",
            "W3BSP1D3R_THREADS": "8",
            "W3BSP1D3R_VT_API_KEY": "test-key",
        }):
            overrides = load_config_from_env()
            assert overrides["url"] == "http://env-target.com"
            assert overrides["threads"] == 8
            assert overrides["vt_api_key"] == "test-key"


# ---------------------------------------------------------------------------
# Checkpoint tests
# ---------------------------------------------------------------------------

class TestCheckpoint(unittest.TestCase):
    """Test checkpoint save/load/clear."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def test_save_and_load(self):
        from scanner.checkpoint import CheckpointManager
        cp = CheckpointManager("test_scan", directory=self.tmpdir, save_interval=0)
        cp.save({"phase": "testing", "progress": 50})
        state = cp.load()
        assert state is not None
        assert state["phase"] == "testing"
        assert state["progress"] == 50

    def test_clear(self):
        from scanner.checkpoint import CheckpointManager
        cp = CheckpointManager("test_scan", directory=self.tmpdir, save_interval=0)
        cp.save({"phase": "done"})
        assert cp.has_checkpoint()
        cp.clear()
        assert not cp.has_checkpoint()

    def test_no_checkpoint_returns_none(self):
        from scanner.checkpoint import CheckpointManager
        cp = CheckpointManager("nonexistent", directory=self.tmpdir)
        assert cp.load() is None

    def test_list_checkpoints(self):
        from scanner.checkpoint import CheckpointManager
        cp1 = CheckpointManager("scan_a", directory=self.tmpdir, save_interval=0)
        cp2 = CheckpointManager("scan_b", directory=self.tmpdir, save_interval=0)
        cp1.save({"phase": "crawl"})
        cp2.save({"phase": "test"})
        listing = cp1.list_checkpoints()
        assert len(listing) == 2


# ---------------------------------------------------------------------------
# Audit tests
# ---------------------------------------------------------------------------

class TestAuditLogger(unittest.TestCase):
    """Test audit trail logging."""

    def test_log_and_read(self):
        from scanner.audit import AuditLogger
        with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as f:
            log_file = f.name

        audit = AuditLogger(log_file=log_file, enabled=True)
        audit.log_scan_start(
            scan_id="abc", target="http://test.com",
            scan_type="full", config={"threads": 4},
        )
        audit.log_finding(
            scan_id="abc", vuln_type="SQLi", severity="Critical",
            url="http://test.com/page", parameter="id", fingerprint="abc123",
        )
        audit.log_scan_complete(
            scan_id="abc", target="http://test.com",
            duration_seconds=60.5, findings_count=1,
            severity_breakdown={"critical": 1, "high": 0, "medium": 0, "low": 0},
        )

        entries = audit.get_entries()
        assert len(entries) == 3
        assert entries[0]["event"] == "scan_start"
        assert entries[1]["event"] == "finding"
        assert entries[2]["event"] == "scan_complete"

        os.unlink(log_file)

    def test_secret_redaction(self):
        from scanner.audit import _redact_secrets
        config = {"username": "admin", "password": "secret", "threads": 4}
        redacted = _redact_secrets(config)
        assert redacted["password"] == "***REDACTED***"
        assert redacted["username"] == "admin"
        assert redacted["threads"] == 4


# ---------------------------------------------------------------------------
# Finding deduplication + fingerprint tests
# ---------------------------------------------------------------------------

class TestFindingFingerprint(unittest.TestCase):
    """Test finding fingerprint and deduplication."""

    def test_same_vuln_same_fingerprint(self):
        from scanner.reporting.models import Finding
        f1 = Finding(vuln_type="SQLi", severity="Critical", url="http://t.com/a",
                     parameter="id", method="GET", payload="x", evidence="y", remediation="z")
        f2 = Finding(vuln_type="SQLi", severity="Critical", url="http://t.com/a",
                     parameter="id", method="GET", payload="different", evidence="y", remediation="z")
        assert f1.fingerprint == f2.fingerprint

    def test_different_param_different_fingerprint(self):
        from scanner.reporting.models import Finding
        f1 = Finding(vuln_type="SQLi", severity="Critical", url="http://t.com/a",
                     parameter="id", method="GET", payload="x", evidence="y", remediation="z")
        f2 = Finding(vuln_type="SQLi", severity="Critical", url="http://t.com/a",
                     parameter="name", method="GET", payload="x", evidence="y", remediation="z")
        assert f1.fingerprint != f2.fingerprint

    def test_fingerprint_in_to_dict(self):
        from scanner.reporting.models import Finding
        f = Finding(vuln_type="SQLi", severity="Critical", url="http://t.com/a",
                    parameter="id", method="GET", payload="x", evidence="y", remediation="z")
        d = f.to_dict()
        assert "fingerprint" in d
        assert len(d["fingerprint"]) == 16

    def test_summary_dedup_enabled(self):
        from scanner.reporting.models import Finding, ScanSummary
        summary = ScanSummary(target_url="http://t.com", scan_type="full", started_at="now")
        f1 = Finding(vuln_type="SQLi", severity="Critical", url="http://t.com/a",
                     parameter="id", method="GET", payload="x", evidence="y", remediation="z")
        f2 = Finding(vuln_type="SQLi", severity="Critical", url="http://t.com/a",
                     parameter="id", method="GET", payload="different", evidence="y", remediation="z")
        assert summary.add_finding(f1) is True
        assert summary.add_finding(f2) is False  # duplicate
        assert summary.total_findings == 1

    def test_summary_dedup_disabled(self):
        from scanner.reporting.models import Finding, ScanSummary
        summary = ScanSummary(target_url="http://t.com", scan_type="full",
                              started_at="now", deduplicate=False)
        f1 = Finding(vuln_type="SQLi", severity="Critical", url="http://t.com/a",
                     parameter="id", method="GET", payload="x", evidence="y", remediation="z")
        f2 = Finding(vuln_type="SQLi", severity="Critical", url="http://t.com/a",
                     parameter="id", method="GET", payload="different", evidence="y", remediation="z")
        assert summary.add_finding(f1) is True
        assert summary.add_finding(f2) is True
        assert summary.total_findings == 2


# ---------------------------------------------------------------------------
# Scope filtering tests
# ---------------------------------------------------------------------------

class TestScopeFiltering(unittest.TestCase):
    """Test URL scope include/exclude filtering."""

    def test_include_pattern(self):
        from scanner.testers.base import set_scope_patterns, is_url_in_scope
        set_scope_patterns(include=["http://target.com/*"], exclude=[])
        assert is_url_in_scope("http://target.com/admin")
        assert not is_url_in_scope("http://other.com/admin")

    def test_exclude_pattern(self):
        from scanner.testers.base import set_scope_patterns, is_url_in_scope
        set_scope_patterns(include=[], exclude=["*/logout*", "*/setup*"])
        assert is_url_in_scope("http://target.com/admin")
        assert not is_url_in_scope("http://target.com/logout")
        assert not is_url_in_scope("http://target.com/setup.php")

    def test_combined_include_exclude(self):
        from scanner.testers.base import set_scope_patterns, is_url_in_scope
        set_scope_patterns(
            include=["http://target.com/*"],
            exclude=["*/logout*"],
        )
        assert is_url_in_scope("http://target.com/page")
        assert not is_url_in_scope("http://target.com/logout")
        assert not is_url_in_scope("http://other.com/page")

    def test_no_patterns_everything_in_scope(self):
        from scanner.testers.base import set_scope_patterns, is_url_in_scope
        set_scope_patterns(include=[], exclude=[])
        assert is_url_in_scope("http://anything.com/whatever")

    def tearDown(self):
        from scanner.testers.base import set_scope_patterns
        set_scope_patterns(include=[], exclude=[])


# ---------------------------------------------------------------------------
# Token bucket rate limiter tests
# ---------------------------------------------------------------------------

class TestTokenBucket(unittest.TestCase):
    """Test token bucket rate limiter."""

    def test_acquire_within_capacity(self):
        from scanner.utils.http import TokenBucket
        bucket = TokenBucket(capacity=3, fill_rate=10)
        assert bucket.acquire(timeout=0.1)
        assert bucket.acquire(timeout=0.1)
        assert bucket.acquire(timeout=0.1)

    def test_acquire_refills(self):
        from scanner.utils.http import TokenBucket
        bucket = TokenBucket(capacity=1, fill_rate=100)
        assert bucket.acquire(timeout=0.1)
        # Should refill quickly at 100/sec
        time.sleep(0.05)
        assert bucket.acquire(timeout=0.1)


# ---------------------------------------------------------------------------
# Request metrics tests
# ---------------------------------------------------------------------------

class TestRequestMetrics(unittest.TestCase):
    """Test request metrics tracking."""

    def test_record_success(self):
        from scanner.utils.http import RequestMetrics
        m = RequestMetrics()
        m.record_request(success=True, bytes_received=500, response_time=0.3)
        snap = m.snapshot()
        assert snap["total_requests"] == 1
        assert snap["successful"] == 1
        assert snap["total_bytes"] == 500

    def test_record_failure(self):
        from scanner.utils.http import RequestMetrics
        m = RequestMetrics()
        m.record_request(success=False, response_time=1.0)
        snap = m.snapshot()
        assert snap["failed"] == 1

    def test_record_retry_and_rate_limit(self):
        from scanner.utils.http import RequestMetrics
        m = RequestMetrics()
        m.record_request(success=True, retried=True, rate_limited=True)
        snap = m.snapshot()
        assert snap["retried"] == 1
        assert snap["rate_limited"] == 1

    def test_average_response_time(self):
        from scanner.utils.http import RequestMetrics
        m = RequestMetrics()
        m.record_request(success=True, response_time=1.0)
        m.record_request(success=True, response_time=3.0)
        snap = m.snapshot()
        assert snap["avg_response_time"] == 2.0


# ---------------------------------------------------------------------------
# Diff comparison tests
# ---------------------------------------------------------------------------

class TestScanDiff(unittest.TestCase):
    """Test scan comparison."""

    def _make_finding(self, vuln_type, url, param):
        from scanner.reporting.models import Finding
        return Finding(vuln_type=vuln_type, severity="High", url=url,
                       parameter=param, method="GET", payload="x",
                       evidence="y", remediation="z")

    def test_new_and_fixed_findings(self):
        from scanner.reporting.models import ScanSummary
        from scanner.reporting.diff_report import compare_scans

        baseline = ScanSummary(target_url="http://t.com", scan_type="full", started_at="t1")
        current = ScanSummary(target_url="http://t.com", scan_type="full", started_at="t2")

        f_old = self._make_finding("SQLi", "http://t.com/a", "id")
        f_same = self._make_finding("XSS", "http://t.com/b", "q")
        f_new = self._make_finding("CSRF", "http://t.com/c", "token")

        baseline.add_finding(f_old)
        baseline.add_finding(f_same)
        current.add_finding(f_same)
        current.add_finding(f_new)

        diff = compare_scans(current, baseline)
        assert diff.total_new == 1
        assert diff.total_fixed == 1
        assert diff.total_unchanged == 1

    def test_improved_flag(self):
        from scanner.reporting.models import ScanSummary
        from scanner.reporting.diff_report import compare_scans

        baseline = ScanSummary(target_url="http://t.com", scan_type="full", started_at="t1")
        current = ScanSummary(target_url="http://t.com", scan_type="full", started_at="t2")

        baseline.add_finding(self._make_finding("SQLi", "http://t.com/a", "id"))
        baseline.add_finding(self._make_finding("XSS", "http://t.com/b", "q"))
        # current has no findings

        diff = compare_scans(current, baseline)
        assert diff.improved is True


# ---------------------------------------------------------------------------
# Webhook format tests
# ---------------------------------------------------------------------------

class TestWebhookFormatting(unittest.TestCase):
    """Test webhook message formatting."""

    def _make_summary(self):
        from scanner.reporting.models import ScanSummary, Finding
        summary = ScanSummary(target_url="http://test.com", scan_type="full",
                              started_at="2024-01-01T00:00:00Z",
                              finished_at="2024-01-01T00:05:00Z")
        summary.add_finding(Finding(
            vuln_type="SQLi", severity="Critical", url="http://test.com/a",
            parameter="id", method="GET", payload="x", evidence="y", remediation="z",
        ))
        return summary

    @patch("scanner.webhooks.requests.post")
    def test_slack_webhook_sent(self, mock_post):
        from scanner.webhooks import WebhookNotifier, WebhookConfig
        mock_post.return_value = MagicMock(status_code=200)

        config = WebhookConfig(enabled=True, slack_url="https://hooks.slack.com/test")
        notifier = WebhookNotifier(config)
        notifier.notify_scan_complete(self._make_summary(), scan_id="test123")

        mock_post.assert_called_once()
        call_kwargs = mock_post.call_args
        payload = call_kwargs.kwargs.get("json") or call_kwargs[1].get("json")
        assert "blocks" in payload

    @patch("scanner.webhooks.requests.post")
    def test_discord_webhook_sent(self, mock_post):
        from scanner.webhooks import WebhookNotifier, WebhookConfig
        mock_post.return_value = MagicMock(status_code=204)

        config = WebhookConfig(enabled=True, discord_url="https://discord.com/api/webhooks/test")
        notifier = WebhookNotifier(config)
        notifier.notify_scan_complete(self._make_summary(), scan_id="test123")

        mock_post.assert_called_once()
        payload = mock_post.call_args.kwargs.get("json") or mock_post.call_args[1].get("json")
        assert "embeds" in payload

    @patch("scanner.webhooks.requests.post")
    def test_on_findings_only_skips_clean(self, mock_post):
        from scanner.webhooks import WebhookNotifier, WebhookConfig
        from scanner.reporting.models import ScanSummary

        config = WebhookConfig(enabled=True, slack_url="https://hooks.slack.com/test",
                               on_findings_only=True)
        notifier = WebhookNotifier(config)
        clean_summary = ScanSummary(target_url="http://test.com", scan_type="full",
                                    started_at="now")
        notifier.notify_scan_complete(clean_summary, scan_id="test123")
        mock_post.assert_not_called()


# ---------------------------------------------------------------------------
# Database tests
# ---------------------------------------------------------------------------

class TestScanDatabase(unittest.TestCase):
    """Test SQLite scan database."""

    def test_save_and_retrieve_scan(self):
        from scanner.db import ScanDatabase
        from scanner.reporting.models import ScanSummary, Finding

        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            db_path = f.name

        db = ScanDatabase(path=db_path, enabled=True)
        summary = ScanSummary(target_url="http://test.com", scan_type="full",
                              started_at="2024-01-01T00:00:00Z",
                              finished_at="2024-01-01T00:05:00Z")
        summary.add_finding(Finding(
            vuln_type="SQLi", severity="Critical", url="http://test.com/a",
            parameter="id", method="GET", payload="x", evidence="y", remediation="z",
        ))

        db.save_scan("test_scan_1", summary)

        history = db.get_scan_history()
        assert len(history) == 1
        assert history[0]["scan_id"] == "test_scan_1"
        assert history[0]["total_findings"] == 1

        findings = db.get_findings_by_scan("test_scan_1")
        assert len(findings) == 1
        assert findings[0]["vuln_type"] == "SQLi"

        db.close()
        os.unlink(db_path)

    def test_severity_trends(self):
        from scanner.db import ScanDatabase
        from scanner.reporting.models import ScanSummary

        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            db_path = f.name

        db = ScanDatabase(path=db_path, enabled=True)
        for i in range(3):
            summary = ScanSummary(target_url="http://test.com", scan_type="full",
                                  started_at=f"2024-01-0{i+1}T00:00:00Z")
            db.save_scan(f"scan_{i}", summary)

        trends = db.get_severity_trends("http://test.com")
        assert len(trends) == 3

        db.close()
        os.unlink(db_path)

    def test_stats(self):
        from scanner.db import ScanDatabase
        from scanner.reporting.models import ScanSummary

        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            db_path = f.name

        db = ScanDatabase(path=db_path, enabled=True)
        summary = ScanSummary(target_url="http://test.com", scan_type="full",
                              started_at="2024-01-01T00:00:00Z")
        db.save_scan("scan_1", summary)

        stats = db.get_stats()
        assert stats["total_scans"] == 1
        assert stats["unique_targets"] == 1

        db.close()
        os.unlink(db_path)


# ---------------------------------------------------------------------------
# Structured logging tests
# ---------------------------------------------------------------------------

class TestStructuredLogging(unittest.TestCase):
    """Test JSON structured logging formatter."""

    def test_json_formatter_output(self):
        import logging
        from scanner.utils.logging_config import JSONFormatter, set_scan_id, set_request_id

        set_scan_id("test_scan")
        set_request_id("req_123")

        formatter = JSONFormatter()
        record = logging.LogRecord(
            name="test", level=logging.WARNING, pathname="", lineno=0,
            msg="Test message", args=(), exc_info=None,
        )
        output = formatter.format(record)
        parsed = json.loads(output)

        assert parsed["message"] == "Test message"
        assert parsed["level"] == "WARNING"
        assert parsed["scan_id"] == "test_scan"
        assert parsed["request_id"] == "req_123"


if __name__ == "__main__":
    unittest.main()
