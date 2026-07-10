"""Tests for Phase 2 C1 — baseline comparison eliminates false positives.

Every error-based / output-based tester must skip signatures that already
appear in the baseline (clean) response.
"""
from __future__ import annotations

from unittest.mock import patch, MagicMock

from scanner.crawler import CrawledPage, CrawledForm, FormField


# ── Helpers ──────────────────────────────────────────────────────────────

def _form(action: str = "http://target/search", method: str = "POST") -> CrawledForm:
    return CrawledForm(
        page_url="http://target/",
        action_url=action,
        method=method,
        fields=[FormField(name="q", field_type="text", value="")],
    )


def _page(url: str = "http://target/") -> CrawledPage:
    return CrawledPage(url=url, status=200)


def _mock_resp(text: str, status: int = 200):
    r = MagicMock()
    r.text = text
    r.content = text.encode()
    r.status_code = status
    r.url = "http://target/search"
    r.headers = {"Content-Type": "text/html"}
    return r


# ── SQLi error-based ─────────────────────────────────────────────────────

class TestSQLiErrorBaseline:
    """_error_based_form / _error_based_get must skip signatures in baseline."""

    @patch("scanner.testers.sqli.http_utils")
    def test_error_in_baseline_skipped_form(self, mock_http):
        """If the exact DB error signature already appears in the baseline, must not fire."""
        from scanner.testers.sqli import SQLiTester

        # The signature "you have an error in your sql syntax" already appears in baseline
        baseline_text = "<html>You have an error in your SQL syntax debug page</html>"
        injected_text = "<html>You have an error in your SQL syntax near '\"'</html>"

        mock_http.post = MagicMock(return_value=_mock_resp(injected_text))
        mock_http.get = MagicMock(return_value=_mock_resp(injected_text))

        tester = SQLiTester()
        result = tester._error_based_form(_form(), "q", baseline_text=baseline_text)
        assert result is False, "Should skip — error signature already in baseline"

    @patch("scanner.testers.sqli.http_utils")
    def test_error_not_in_baseline_fires_form(self, mock_http):
        """If the baseline is clean, a real SQL error must fire."""
        from scanner.testers.sqli import SQLiTester

        baseline_text = "<html>Welcome to our site</html>"
        injected_text = "<html>You have an error in your SQL syntax near '\"'</html>"

        mock_http.post = MagicMock(return_value=_mock_resp(injected_text))

        tester = SQLiTester()
        result = tester._error_based_form(_form(), "q", baseline_text=baseline_text)
        assert result is True, "Should fire — SQL error only in injected response"

    @patch("scanner.testers.sqli.http_utils")
    def test_error_in_baseline_skipped_get(self, mock_http):
        from scanner.testers.sqli import SQLiTester

        # "microsoft sql server" is a DB_ERROR_SIGNATURE — present in baseline too
        baseline_text = "<html>Powered by Microsoft SQL Server 2019</html>"
        injected_text = "<html>Microsoft SQL Server error near syntax</html>"

        mock_http.get = MagicMock(return_value=_mock_resp(injected_text))

        tester = SQLiTester()
        result = tester._error_based_get("http://target/?q=1", "q", baseline_text=baseline_text)
        assert result is False, "Should skip — 'microsoft sql server' already in baseline"


# ── NoSQL error-based ────────────────────────────────────────────────────

class TestNoSQLErrorBaseline:
    @patch("scanner.testers.nosql_injection.http_utils")
    def test_mongo_signature_in_baseline_skipped(self, mock_http):
        from scanner.testers.nosql_injection import NoSQLInjectionTester

        # "MongoError" is the actual matched signature — must be in baseline
        baseline_text = "<html>Debug: MongoError handler enabled</html>"
        injected_text = "<html>Debug: MongoError: bad query form</html>"

        # First call = baseline, subsequent calls = injected
        call_count = [0]
        def side_effect(*args, **kwargs):
            call_count[0] += 1
            if call_count[0] == 1:
                return _mock_resp(baseline_text)
            return _mock_resp(injected_text)

        mock_http.post = MagicMock(side_effect=side_effect)

        tester = NoSQLInjectionTester()
        form = _form()
        tester._test_form_error(form, "q", "http://target/")
        assert len(tester.findings) == 0, "Should skip — 'MongoError' already in baseline"

    @patch("scanner.testers.nosql_injection.http_utils")
    def test_mongo_error_fires_when_baseline_clean(self, mock_http):
        from scanner.testers.nosql_injection import NoSQLInjectionTester

        baseline_text = "<html>Welcome</html>"
        injected_text = "<html>MongoError: bad query</html>"

        call_count = [0]
        def side_effect(*args, **kwargs):
            call_count[0] += 1
            if call_count[0] == 1:
                return _mock_resp(baseline_text)
            return _mock_resp(injected_text)

        mock_http.post = MagicMock(side_effect=side_effect)

        tester = NoSQLInjectionTester()
        form = _form()
        tester._test_form_error(form, "q", "http://target/")
        assert len(tester.findings) >= 1, "Should fire — MongoError only in injected resp"


# ── CMDi output-based ────────────────────────────────────────────────────

class TestCMDiBaseline:
    @patch("scanner.testers.cmdi.http_utils")
    def test_root_in_baseline_skipped(self, mock_http):
        """If 'root:' already appears in baseline, path traversal via cmdi must not fire."""
        from scanner.testers.cmdi import CmdInjectionTester

        baseline_text = "<html>root: admin panel</html>"
        injected_text = "<html>root: admin panel</html>"

        call_count = [0]
        def side_effect(*args, **kwargs):
            call_count[0] += 1
            if call_count[0] == 1:
                return _mock_resp(baseline_text)
            return _mock_resp(injected_text)

        mock_http.post = MagicMock(side_effect=side_effect)

        tester = CmdInjectionTester()
        result = tester._output_form(_form(), "q")
        assert result is False, "Should skip — 'root' already in baseline"

    @patch("scanner.testers.cmdi.http_utils")
    def test_uid_fires_with_regex_match(self, mock_http):
        """Real uid= output from `id` command must fire."""
        from scanner.testers.cmdi import CmdInjectionTester

        baseline_text = "<html>Welcome</html>"
        injected_text = "<html>uid=33(www-data) gid=33(www-data) groups=33</html>"

        call_count = [0]
        def side_effect(*args, **kwargs):
            call_count[0] += 1
            if call_count[0] == 1:
                return _mock_resp(baseline_text)
            return _mock_resp(injected_text)

        mock_http.post = MagicMock(side_effect=side_effect)

        tester = CmdInjectionTester()
        result = tester._output_form(_form(), "q")
        assert result is True, "Should fire — uid=33(www-data) gid=33 is real cmd output"

    @patch("scanner.testers.cmdi.http_utils")
    def test_uid_without_regex_match_skipped(self, mock_http):
        """A page that casually mentions 'uid=' but not in id-command format must not fire."""
        from scanner.testers.cmdi import CmdInjectionTester

        baseline_text = "<html>Welcome</html>"
        injected_text = "<html>Your uid=something is invalid</html>"

        call_count = [0]
        def side_effect(*args, **kwargs):
            call_count[0] += 1
            if call_count[0] == 1:
                return _mock_resp(baseline_text)
            return _mock_resp(injected_text)

        mock_http.post = MagicMock(side_effect=side_effect)

        tester = CmdInjectionTester()
        result = tester._output_form(_form(), "q")
        assert result is False, "Should skip — uid= without proper format"


# ── Path Traversal ───────────────────────────────────────────────────────

class TestPathTraversalBaseline:
    @patch("scanner.testers.path_traversal.http_utils")
    def test_root_colon_in_baseline_skipped(self, mock_http):
        from scanner.testers.path_traversal import PathTraversalTester

        baseline_text = "<html>root: admin section of the site</html>"
        injected_text = "<html>root: admin section of the site</html>"

        call_count = [0]
        def side_effect(*args, **kwargs):
            call_count[0] += 1
            if call_count[0] == 1:
                return _mock_resp(baseline_text)
            return _mock_resp(injected_text)

        mock_http.post = MagicMock(side_effect=side_effect)
        mock_http.get = MagicMock(side_effect=side_effect)

        tester = PathTraversalTester()
        tester._test_form(_form(), "q")
        assert len(tester.findings) == 0, "Should skip — 'root:' already in baseline"

    @patch("scanner.testers.path_traversal.http_utils")
    def test_real_passwd_fires(self, mock_http):
        from scanner.testers.path_traversal import PathTraversalTester

        baseline_text = "<html>Welcome</html>"
        injected_text = "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin"

        call_count = [0]
        def side_effect(*args, **kwargs):
            call_count[0] += 1
            if call_count[0] == 1:
                return _mock_resp(baseline_text)
            return _mock_resp(injected_text)

        mock_http.post = MagicMock(side_effect=side_effect)
        mock_http.get = MagicMock(side_effect=side_effect)

        tester = PathTraversalTester()
        tester._test_form(_form(), "q")
        assert len(tester.findings) >= 1, "Should fire — real /etc/passwd content"


# ── Step 2: Realistic FP simulation scenarios ────────────────────────────

class TestRealisticFPScenarios:
    """
    Three scenarios that triggered false positives pre-baseline.
    All must produce zero findings now.
    """

    @patch("scanner.testers.sqli.http_utils")
    def test_fp_mysql_branding_in_footer(self, mock_http):
        """
        Scenario A: A CMS proudly says 'MySQL Community Server' and also shows
        'you have an error in your SQL syntax' as part of a debug/help blurb
        in its footer on EVERY page — including baseline.
        """
        from scanner.testers.sqli import SQLiTester

        page_body = (
            "<html><body>"
            "<h1>Welcome to AdminPanel</h1>"
            "<footer>Powered by MySQL Community Server 8.0 &mdash; "
            "you have an error in your SQL syntax? Check our FAQ.</footer>"
            "</body></html>"
        )
        # baseline and injected return the same body — no real vuln
        mock_http.post = MagicMock(return_value=_mock_resp(page_body))
        mock_http.get = MagicMock(return_value=_mock_resp(page_body))

        tester = SQLiTester()
        result = tester._error_based_form(_form(), "q", baseline_text=page_body)
        assert result is False, (
            "FP scenario A: page footer always contains SQL-error-like text → must NOT fire"
        )

    @patch("scanner.testers.nosql_injection.http_utils")
    def test_fp_mongoerror_in_debug_comment(self, mock_http):
        """
        Scenario B: A Node.js app includes an HTML comment with
        'MongoError: cannot connect to replica set' on every page for
        debugging — present in baseline too.
        """
        from scanner.testers.nosql_injection import NoSQLInjectionTester

        page_body = (
            "<html><!-- MongoError: cannot connect to replica set primary -->"
            "<body><h1>App</h1></body></html>"
        )

        # Baseline + all injected responses return the same body
        mock_http.post = MagicMock(return_value=_mock_resp(page_body))

        tester = NoSQLInjectionTester()
        tester._test_form_error(_form(), "q", "http://target/")
        assert len(tester.findings) == 0, (
            "FP scenario B: MongoError in HTML comment on every page → must NOT fire"
        )

    @patch("scanner.testers.path_traversal.http_utils")
    def test_fp_passwd_in_tutorial_page(self, mock_http):
        """
        Scenario C: A security-tutorial site shows /etc/passwd contents
        in a <pre> block as educational material — present in baseline too.
        Path Traversal must NOT fire.
        """
        from scanner.testers.path_traversal import PathTraversalTester

        tutorial_body = (
            "<html><body><h1>Linux Basics</h1>"
            "<pre>root:x:0:0:root:/root:/bin/bash\n"
            "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
            "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin</pre>"
            "</body></html>"
        )

        # Same body for baseline and injected
        mock_http.post = MagicMock(return_value=_mock_resp(tutorial_body))
        mock_http.get = MagicMock(return_value=_mock_resp(tutorial_body))

        tester = PathTraversalTester()
        tester._test_form(_form(), "q")
        assert len(tester.findings) == 0, (
            "FP scenario C: /etc/passwd in tutorial page → must NOT fire"
        )
