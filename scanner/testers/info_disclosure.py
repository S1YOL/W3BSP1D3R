from __future__ import annotations
"""
scanner/testers/info_disclosure.py
-------------------------------------
Information disclosure tester — finds leaked sensitive data in
HTML comments, error messages, debug output, and response metadata.

Checks for:
  - HTML comments containing credentials, TODOs, internal IPs
  - Stack traces and debug error messages
  - Internal IP addresses leaked in headers or body
  - Source code fragments in responses
  - Default error pages revealing technology/version
  - Autocomplete enabled on sensitive fields
"""

import logging
import re

from scanner.testers.base import BaseTester
from scanner.crawler import CrawledPage
from scanner.reporting.models import Finding, Severity
from scanner.utils import http as http_utils

logger = logging.getLogger(__name__)

# Patterns to find in HTML comments
_COMMENT_PATTERNS = [
    (r'(?i)(password|passwd|pwd)\s*[:=]\s*\S+', "Password in HTML comment"),
    (r'(?i)(api[_-]?key|apikey|secret[_-]?key)\s*[:=]\s*\S+', "API key in HTML comment"),
    (r'(?i)(username|user)\s*[:=]\s*\S+', "Username in HTML comment"),
    (r'(?i)TODO\s*:', "TODO comment (may leak development info)"),
    (r'(?i)FIXME\s*:', "FIXME comment (may leak vulnerability info)"),
    (r'(?i)HACK\s*:', "HACK comment (may indicate workaround)"),
    (r'(?i)BUG\s*:', "BUG comment (may leak known issues)"),
    (r'(?i)(jdbc|mysql|postgres|mongodb|redis)://[^\s<"]+', "Database connection string in comment"),
]

# Internal/private IP patterns
_INTERNAL_IP_PATTERN = re.compile(
    r'\b(?:'
    r'10\.\d{1,3}\.\d{1,3}\.\d{1,3}|'
    r'172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|'
    r'192\.168\.\d{1,3}\.\d{1,3}|'
    r'127\.\d{1,3}\.\d{1,3}\.\d{1,3}'
    r')\b'
)

# Stack trace indicators
_STACK_TRACE_PATTERNS = [
    (r'Traceback \(most recent call last\)', "Python stack trace"),
    (r'at \w+\.\w+\([\w.]+:\d+\)', "Java stack trace"),
    (r'#\d+ [\w\\/:]+\.php\(\d+\)', "PHP stack trace"),
    (r'System\.(?:NullReferenceException|ArgumentException|InvalidOperationException)',
     ".NET exception"),
    (r'Microsoft\.AspNetCore\.\w+', "ASP.NET Core stack trace"),
    (r'node_modules/[^\s]+\.js:\d+', "Node.js stack trace"),
    (r'at Object\.<anonymous>.*\.js:\d+:\d+', "Node.js stack trace"),
    (r'Fatal error:.*in /\w+', "PHP fatal error"),
    (r'Warning:.*in /\w+.*on line \d+', "PHP warning with path"),
    (r'undefined is not a function', "JavaScript error leaked"),
    (r'SQLSTATE\[\w+\]', "SQL state error leaked"),
    (r'pg_query\(\): ERROR:', "PostgreSQL error leaked"),
    (r'mysql_fetch_array\(\)', "MySQL error leaked"),
]

# Source code indicators
_SOURCE_CODE_PATTERNS = [
    (r'<\?php\s', "PHP source code exposed"),
    (r'<%@?\s*(page|import|taglib)', "JSP source code exposed"),
    (r'<asp:', "ASP.NET source code exposed"),
]

# Sensitive form field patterns (autocomplete should be off)
_SENSITIVE_FIELDS = {"password", "passwd", "credit-card", "cc-number",
                     "card-number", "cvv", "ssn", "social-security"}


class InfoDisclosureTester(BaseTester):
    """Detect information disclosure in HTML, headers, and error messages."""

    def __init__(self) -> None:
        super().__init__(name="Information Disclosure")

    def run(self, pages: list[CrawledPage]) -> list[Finding]:
        if not pages:
            return self.findings

        pages = self._filter_pages_by_scope(pages)

        for page in pages:
            self._count_test()
            try:
                resp = http_utils.get(page.url)
            except Exception:
                continue

            body = resp.text

            # Check HTML comments
            self._check_comments(body, page.url)

            # Check for internal IP leaks
            self._check_internal_ips(body, resp.headers, page.url)

            # Check for stack traces
            self._check_stack_traces(body, page.url)

            # Check for source code
            self._check_source_code(body, page.url)

            # Check for autocomplete on sensitive fields
            self._check_autocomplete(body, page.url)

        # Check error page disclosure
        if pages:
            self._check_error_pages(pages[0].url)

        return self.findings

    def _check_comments(self, body: str, url: str) -> None:
        """Scan HTML comments for sensitive information."""
        comments = re.findall(r'<!--(.*?)-->', body, re.DOTALL)
        for comment in comments:
            for pattern, desc in _COMMENT_PATTERNS:
                match = re.search(pattern, comment)
                if match:
                    snippet = comment.strip()[:200]
                    self._log_finding(Finding(
                        vuln_type="Information Disclosure (HTML Comment)",
                        severity=Severity.MEDIUM,
                        url=url,
                        parameter="HTML comment",
                        method="GET",
                        payload="View page source → HTML comments",
                        evidence=f"{desc}: <!-- {snippet} -->",
                        remediation=(
                            "Remove sensitive information from HTML comments before "
                            "deployment. Use a build process that strips comments "
                            "from production HTML. Never include credentials, API keys, "
                            "or internal details in client-facing code."
                        ),
                    ))
                    break  # One finding per comment is enough

    def _check_internal_ips(self, body: str, headers: dict, url: str) -> None:
        """Check for leaked internal/private IP addresses."""
        # Check headers
        for header, value in headers.items():
            ips = _INTERNAL_IP_PATTERN.findall(str(value))
            if ips:
                self._log_finding(Finding(
                    vuln_type="Internal IP Address Disclosure",
                    severity=Severity.LOW,
                    url=url,
                    parameter=f"Header: {header}",
                    method="GET",
                    payload=f"Check {header} header",
                    evidence=f"Internal IP(s) in {header}: {', '.join(ips)}",
                    remediation=(
                        "Configure your reverse proxy to strip internal IP addresses "
                        "from response headers. Check X-Forwarded-For, Via, and "
                        "custom headers for internal network information."
                    ),
                ))
                return  # One finding is enough

        # Check body
        ips = _INTERNAL_IP_PATTERN.findall(body)
        if ips:
            unique_ips = list(set(ips))[:5]
            self._log_finding(Finding(
                vuln_type="Internal IP Address Disclosure",
                severity=Severity.LOW,
                url=url,
                parameter="Response body",
                method="GET",
                payload="Inspect response body",
                evidence=f"Internal IP(s) found in page: {', '.join(unique_ips)}",
                remediation=(
                    "Remove internal IP addresses from production responses. "
                    "Check error messages, JavaScript configuration, and HTML comments."
                ),
            ))

    def _check_stack_traces(self, body: str, url: str) -> None:
        """Check for stack traces and detailed error messages."""
        for pattern, desc in _STACK_TRACE_PATTERNS:
            match = re.search(pattern, body)
            if match:
                snippet = body[max(0, match.start() - 50):match.end() + 100][:300]
                self._log_finding(Finding(
                    vuln_type="Stack Trace / Debug Info Exposed",
                    severity=Severity.MEDIUM,
                    url=url,
                    parameter="Response body",
                    method="GET",
                    payload="Trigger error condition",
                    evidence=f"{desc} detected: {snippet}",
                    remediation=(
                        "Disable detailed error messages in production. "
                        "Use custom error pages that don't reveal stack traces, "
                        "file paths, or framework internals. "
                        "Django: DEBUG=False. "
                        "PHP: display_errors=Off. "
                        "ASP.NET: customErrors mode='On'."
                    ),
                ))
                return  # One stack trace finding per page

    def _check_source_code(self, body: str, url: str) -> None:
        """Check if server-side source code is exposed in responses."""
        for pattern, desc in _SOURCE_CODE_PATTERNS:
            if re.search(pattern, body):
                self._log_finding(Finding(
                    vuln_type="Source Code Exposure",
                    severity=Severity.HIGH,
                    url=url,
                    parameter="Response body",
                    method="GET",
                    payload="View raw response",
                    evidence=desc,
                    remediation=(
                        "Server-side code is being rendered as plain text instead "
                        "of being executed. Check web server configuration to ensure "
                        "the correct handler is processing these file types."
                    ),
                ))
                return

    def _check_autocomplete(self, body: str, url: str) -> None:
        """Check if sensitive form fields have autocomplete enabled."""
        # Look for password fields without autocomplete="off"
        password_fields = re.findall(
            r'<input[^>]*type=["\']password["\'][^>]*>', body, re.IGNORECASE
        )
        for field_html in password_fields:
            if 'autocomplete="off"' not in field_html.lower() and \
               "autocomplete='off'" not in field_html.lower() and \
               'autocomplete="new-password"' not in field_html.lower():
                self._log_finding(Finding(
                    vuln_type="Autocomplete Enabled on Sensitive Field",
                    severity=Severity.LOW,
                    url=url,
                    parameter="password field",
                    method="GET",
                    payload="Check form HTML",
                    evidence=f"Password field without autocomplete='off': {field_html[:150]}",
                    remediation=(
                        "Add autocomplete='off' or autocomplete='new-password' to "
                        "sensitive form fields (passwords, credit cards, SSNs) to "
                        "prevent browsers from caching credentials."
                    ),
                ))
                return

    def _check_error_pages(self, base_url: str) -> None:
        """Trigger error responses and check for information disclosure."""
        from urllib.parse import urlparse
        parsed = urlparse(base_url)
        origin = f"{parsed.scheme}://{parsed.netloc}"

        error_triggers = [
            (origin + "/w3bsp1d3r-404-test-page", "404 error page"),
            (origin + "/%00", "Null byte error"),
            (origin + "/'" , "Quote character error"),
        ]

        for error_url, desc in error_triggers:
            self._count_test()
            try:
                resp = http_utils.get(error_url)
            except Exception:
                continue

            body = resp.text.lower()

            # Check if error page reveals technology details
            tech_indicators = [
                ("apache", "Apache version disclosed"),
                ("nginx", "Nginx version disclosed"),
                ("iis", "IIS version disclosed"),
                ("tomcat", "Tomcat version disclosed"),
                ("django", "Django framework disclosed"),
                ("laravel", "Laravel framework disclosed"),
                ("express", "Express.js disclosed"),
                ("asp.net", "ASP.NET disclosed"),
            ]

            for tech, tech_desc in tech_indicators:
                if tech in body:
                    # Look for version numbers near the tech name
                    version_match = re.search(
                        rf'{tech}[\s/]*(\d+\.\d+[\.\d]*)',
                        resp.text, re.IGNORECASE
                    )
                    if version_match:
                        self._log_finding(Finding(
                            vuln_type="Error Page Information Disclosure",
                            severity=Severity.LOW,
                            url=error_url,
                            parameter=desc,
                            method="GET",
                            payload=f"Request {error_url}",
                            evidence=f"{tech_desc}: {version_match.group(0)}",
                            remediation=(
                                "Configure custom error pages that don't reveal "
                                "server software or version information."
                            ),
                        ))
                        return
