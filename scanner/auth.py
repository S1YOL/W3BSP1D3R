from __future__ import annotations
"""
scanner/auth.py
----------------
Authentication handler for the web vulnerability scanner.

Supports:
  1. DVWA (Damn Vulnerable Web Application) — sets the security level to "low"
     and handles the CSRF token embedded in the DVWA login form.
  2. Generic form-based login — automatically finds the login form on a page
     and submits credentials, then validates by checking for a redirect or
     the disappearance of a "login" keyword in the landing page.

Security concept:
  Web applications with form-based auth often embed a CSRF token in the login
  form (a hidden input). This module demonstrates how to extract and replay
  that token — the same technique used by automated scanners and web crawlers.
  DVWA specifically uses a `user_token` hidden field generated per-session.
"""

import logging
from urllib.parse import urljoin

from bs4 import BeautifulSoup

from scanner.utils import http as http_utils
from scanner.utils.display import console, print_success, print_error, print_warning

logger = logging.getLogger(__name__)


class AuthHandler:
    """
    Manages authenticated access to a target web application.

    After a successful login the session cookie is stored in the shared
    requests.Session (via http_utils), so all subsequent requests from
    any tester module will automatically carry the auth cookie.
    """

    # Tokens that suggest we're looking at a login page
    _LOGIN_INDICATORS = {"login", "signin", "sign_in", "log_in", "authenticate"}

    # Tokens that suggest we successfully reached an authenticated page
    _AUTH_INDICATORS  = {"logout", "signout", "dashboard", "profile", "welcome"}

    def __init__(self, base_url: str, username: str, password: str) -> None:
        """
        Args:
            base_url : Root URL of the target application.
            username : Login username.
            password : Login password.
        """
        self.base_url = base_url.rstrip("/")
        self.username = username
        self.password = password
        self._authenticated = False

    @property
    def is_authenticated(self) -> bool:
        return self._authenticated

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def login(self) -> bool:
        """
        Attempt to authenticate against the target application.

        Tries DVWA-specific login first, then falls back to generic
        form-based login discovery.

        Returns:
            True if authentication succeeded, False otherwise.
        """
        if self._try_dvwa_login():
            return True
        if self._try_generic_login():
            return True

        print_error(
            "Authentication failed. Check --login-user / --login-pass "
            "and ensure the target is reachable."
        )
        return False

    # ------------------------------------------------------------------
    # DVWA-specific login
    # ------------------------------------------------------------------

    def _try_dvwa_login(self) -> bool:
        """
        DVWA embeds a `user_token` CSRF token in its login form.
        We must:
          1. GET the login page to obtain a session cookie + user_token.
          2. POST credentials + user_token back to the login endpoint.
          3. GET /dvwa/setup.php to check setup state (optional).
          4. Set the DVWA security level to "low" via /dvwa/security.php.

        Returns True if the DVWA security.php page is reachable post-login.
        """
        login_url    = urljoin(self.base_url + "/", "login.php")
        security_url = urljoin(self.base_url + "/", "security.php")

        console.print(f"  [dim]Trying DVWA login at {login_url}[/dim]")

        # --- Step 1: Fetch login page to grab session cookie + CSRF token ---
        try:
            resp = http_utils.get(login_url)
        except Exception as exc:
            logger.debug("DVWA login page fetch failed: %s", exc)
            return False

        if "dvwa" not in resp.text.lower() and "damn" not in resp.text.lower():
            logger.debug("Page doesn't look like DVWA — skipping DVWA path")
            return False

        token = self._extract_csrf_token(resp.text, field_name="user_token")
        if not token:
            logger.debug("No user_token found — may not be DVWA")
            return False

        # --- Step 2: POST credentials ---
        login_data = {
            "username":   self.username,
            "password":   self.password,
            "Login":      "Login",
            "user_token": token,
        }
        try:
            resp = http_utils.post(login_url, data=login_data)
        except Exception as exc:
            logger.debug("DVWA POST failed: %s", exc)
            return False

        # After successful DVWA login we land on index.php
        if "login.php" in resp.url and "logout" not in resp.text.lower():
            logger.debug("DVWA login failed — still on login page")
            return False

        # --- Step 3: Set DVWA security level to "low" so all vulns fire ---
        self._set_dvwa_security_low(security_url)

        print_success(f"Authenticated to DVWA as '{self.username}' (security=low)")
        self._authenticated = True
        return True

    def _set_dvwa_security_low(self, security_url: str) -> None:
        """
        POST to DVWA's security settings page to set difficulty to 'low'.
        This ensures all vulnerability modules are exploitable so the scanner
        can demonstrate positive detection.
        """
        try:
            resp  = http_utils.get(security_url)
            token = self._extract_csrf_token(resp.text, field_name="user_token")
            data  = {
                "security":   "low",
                "seclev_submit": "Submit",
                "user_token": token or "",
            }
            http_utils.post(security_url, data=data)
            logger.debug("DVWA security set to 'low'")
        except Exception as exc:
            print_warning(f"Could not set DVWA security level: {exc}")

    # ------------------------------------------------------------------
    # Generic form-based login
    # ------------------------------------------------------------------

    def _try_generic_login(self) -> bool:
        """
        Generic login strategy:
          1. Check if the base URL itself is a login page; if not, look for
             a /login, /signin, or /account/login path.
          2. Parse the form, fill username/password fields, and POST.
          3. Confirm success by checking for auth indicators in the response.

        Returns True if post-login page contains auth indicator tokens.
        """
        login_url = self._discover_login_url()
        if not login_url:
            print_warning("Could not discover a login URL — skipping authentication")
            return False

        console.print(f"  [dim]Trying generic login at {login_url}[/dim]")

        try:
            resp = http_utils.get(login_url)
        except Exception as exc:
            logger.debug("Could not reach login URL: %s", exc)
            return False

        soup = BeautifulSoup(resp.text, "lxml")
        form = self._find_login_form(soup)
        if not form:
            logger.debug("No login form found at %s", login_url)
            return False

        # Build submission dict from all form fields
        action  = form.get("action", login_url)
        post_url = urljoin(login_url, action) if action else login_url
        form_data = self._build_form_data(form, resp.text)

        try:
            resp = http_utils.post(post_url, data=form_data)
        except Exception as exc:
            logger.debug("Login POST failed: %s", exc)
            return False

        body_lower = resp.text.lower()
        if any(ind in body_lower for ind in self._AUTH_INDICATORS):
            print_success(f"Authenticated (generic login) as '{self.username}'")
            self._authenticated = True
            return True

        if any(ind in body_lower for ind in self._LOGIN_INDICATORS):
            logger.debug("Still seeing login page — credentials may be wrong")
            return False

        # Ambiguous — assume success if we got a 200 without a login form
        if resp.status_code == 200 and not self._find_login_form(BeautifulSoup(resp.text, "lxml")):
            print_success(f"Authenticated (generic login) as '{self.username}' (heuristic)")
            self._authenticated = True
            return True

        return False

    def _discover_login_url(self) -> str | None:
        """
        Try common login path suffixes and return the first one that returns
        a page containing a login form.
        """
        candidates = [
            self.base_url,
            urljoin(self.base_url + "/", "login"),
            urljoin(self.base_url + "/", "login.php"),
            urljoin(self.base_url + "/", "signin"),
            urljoin(self.base_url + "/", "account/login"),
            urljoin(self.base_url + "/", "user/login"),
            urljoin(self.base_url + "/", "auth/login"),
        ]
        for url in candidates:
            try:
                resp = http_utils.get(url)
                soup = BeautifulSoup(resp.text, "lxml")
                if self._find_login_form(soup):
                    return url
            except Exception:
                continue
        return None

    # ------------------------------------------------------------------
    # HTML parsing helpers
    # ------------------------------------------------------------------

    def _find_login_form(self, soup: BeautifulSoup):
        """
        Locate the login form in parsed HTML.

        Strategy:
          1. Look for a <form> containing both a password input and a text/
             email input — that's almost certainly a login form.
          2. Fall back to the first form with a password field.
        """
        for form in soup.find_all("form"):
            inputs = form.find_all("input")
            types  = {inp.get("type", "text").lower() for inp in inputs}
            if "password" in types and ("text" in types or "email" in types):
                return form

        # Fallback — any form with a password field
        for form in soup.find_all("form"):
            if form.find("input", {"type": "password"}):
                return form

        return None

    def _build_form_data(self, form, page_html: str) -> dict:
        """
        Extract all input fields from a form and set username/password values.

        Handles:
          - Hidden fields (including CSRF tokens) — preserved as-is
          - Text / email / username fields — filled with self.username
          - Password fields — filled with self.password
          - Submit buttons — kept with their value

        Returns a dict ready to pass to requests.post(data=...).
        """
        data: dict[str, str] = {}

        for inp in form.find_all(["input", "button"]):
            name  = inp.get("name")
            value = inp.get("value", "")
            itype = inp.get("type", "text").lower()

            if not name:
                continue

            if itype == "password":
                data[name] = self.password
            elif itype in ("text", "email"):
                # Heuristic: if the field name hints at a username, fill it
                name_lower = name.lower()
                if any(k in name_lower for k in ("user", "email", "login", "name", "account")):
                    data[name] = self.username
                else:
                    data[name] = value  # keep default for unknown fields
            elif itype == "hidden":
                data[name] = value  # preserve CSRF tokens etc.
            elif itype in ("submit", "button"):
                data[name] = value
            else:
                data[name] = value

        return data

    def _extract_csrf_token(self, html: str, field_name: str = "user_token") -> str | None:
        """
        Extract a CSRF token from a hidden form input field.

        Args:
            html       : Raw HTML string of the page.
            field_name : The `name` attribute of the hidden input to extract.

        Returns:
            The token value string, or None if not found.
        """
        soup  = BeautifulSoup(html, "lxml")
        field = soup.find("input", {"name": field_name, "type": "hidden"})
        if field:
            token = field.get("value")
            logger.debug("Extracted CSRF token '%s': %s…", field_name, (token or "")[:12])
            return token
        return None
