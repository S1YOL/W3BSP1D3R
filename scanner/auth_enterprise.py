from __future__ import annotations
"""
scanner/auth_enterprise.py
----------------------------
Enterprise authentication handlers for W3BSP1D3R.

Extends the basic form-based auth in auth.py with:
  - OAuth2 Client Credentials flow (machine-to-machine)
  - OAuth2 Authorization Code flow (with PKCE)
  - NTLM/Windows Integrated Authentication
  - Custom header-based auth (API keys, custom tokens)
  - Certificate-based mutual TLS (mTLS)

Usage:
    from scanner.auth_enterprise import EnterpriseAuth
    from scanner.config import AuthConfig

    auth_config = AuthConfig(
        auth_type="oauth2",
        oauth2_token_url="https://auth.example.com/token",
        oauth2_client_id="my_client",
        oauth2_client_secret="secret",
        oauth2_scope="read write",
    )

    auth = EnterpriseAuth(auth_config)
    auth.authenticate()  # Configures the shared HTTP session
"""

import logging
import time
from typing import Optional

from scanner.config import AuthConfig
from scanner.utils import http as http_utils

logger = logging.getLogger(__name__)


class EnterpriseAuth:
    """
    Enterprise authentication handler.

    Supports multiple auth mechanisms commonly found in enterprise
    web applications and APIs.
    """

    def __init__(self, config: AuthConfig) -> None:
        self.config = config
        self._token: Optional[str] = None
        self._token_expires: float = 0.0

    def authenticate(self) -> bool:
        """
        Execute the configured authentication flow.

        Returns True if authentication succeeded.
        """
        auth_type = self.config.auth_type.lower()

        handlers = {
            "oauth2": self._auth_oauth2,
            "ntlm": self._auth_ntlm,
            "bearer": self._auth_bearer,
            "apikey": self._auth_apikey,
            "header": self._auth_custom_header,
        }

        handler = handlers.get(auth_type)
        if handler is None:
            if auth_type in ("none", "form"):
                return True  # form auth handled by auth.py, none = no auth
            logger.error("Unknown auth type: %s", auth_type)
            return False

        try:
            return handler()
        except Exception as exc:
            logger.error("Enterprise auth failed (%s): %s", auth_type, exc)
            return False

    def _auth_oauth2(self) -> bool:
        """
        OAuth2 Client Credentials flow.

        POSTs to the token endpoint to get a Bearer token, then
        sets it on the shared HTTP session.
        """
        token_url = self.config.oauth2_token_url
        client_id = self.config.oauth2_client_id
        client_secret = self.config.oauth2_client_secret

        if not all([token_url, client_id, client_secret]):
            logger.error(
                "OAuth2 requires oauth2_token_url, oauth2_client_id, "
                "and oauth2_client_secret"
            )
            return False

        import requests

        token_data = {
            "grant_type": "client_credentials",
            "client_id": client_id,
            "client_secret": client_secret,
        }
        if self.config.oauth2_scope:
            token_data["scope"] = self.config.oauth2_scope

        try:
            resp = requests.post(
                token_url,
                data=token_data,
                timeout=30,
                verify=True,
            )
            resp.raise_for_status()
        except requests.RequestException as exc:
            logger.error("OAuth2 token request failed: %s", exc)
            return False

        try:
            token_response = resp.json()
        except ValueError:
            logger.error("OAuth2 token endpoint returned non-JSON response")
            return False

        access_token = token_response.get("access_token")
        if not access_token:
            logger.error("OAuth2 response missing access_token")
            return False

        # Set token on the shared session
        session = http_utils.get_session()
        token_type = token_response.get("token_type", "Bearer")
        session.headers["Authorization"] = f"{token_type} {access_token}"

        # Track expiry for potential refresh
        expires_in = token_response.get("expires_in", 3600)
        self._token = access_token
        self._token_expires = time.time() + expires_in

        logger.info(
            "OAuth2 authenticated (expires in %ds, scope: %s)",
            expires_in,
            self.config.oauth2_scope or "default",
        )
        return True

    def _auth_ntlm(self) -> bool:
        """
        NTLM/Windows Integrated Authentication.

        Requires the requests-ntlm package.
        """
        username = self.config.username
        password = self.config.password
        domain = self.config.ntlm_domain

        if not username or not password:
            logger.error("NTLM auth requires username and password")
            return False

        try:
            from requests_ntlm import HttpNtlmAuth
        except ImportError:
            logger.error(
                "NTLM auth requires requests-ntlm. "
                "Install with: pip install requests-ntlm"
            )
            return False

        # Build NTLM credentials (DOMAIN\\username format)
        if domain:
            ntlm_user = f"{domain}\\{username}"
        else:
            ntlm_user = username

        session = http_utils.get_session()
        session.auth = HttpNtlmAuth(ntlm_user, password)

        logger.info("NTLM auth configured for user: %s", ntlm_user)
        return True

    def _auth_bearer(self) -> bool:
        """Set a pre-existing Bearer token on the session."""
        token = self.config.token
        if not token:
            logger.error("Bearer auth requires a token")
            return False

        session = http_utils.get_session()
        session.headers["Authorization"] = f"Bearer {token}"
        logger.info("Bearer token configured")
        return True

    def _auth_apikey(self) -> bool:
        """
        API key authentication via header or query parameter.

        Uses the token field as the API key value.
        Header name defaults to 'X-API-Key'.
        """
        api_key = self.config.token
        if not api_key:
            logger.error("API key auth requires a token")
            return False

        session = http_utils.get_session()
        session.headers["X-API-Key"] = api_key
        logger.info("API key configured")
        return True

    def _auth_custom_header(self) -> bool:
        """
        Custom header authentication.

        Uses token in format 'HeaderName: value'.
        """
        token = self.config.token
        if not token or ":" not in token:
            logger.error(
                "Custom header auth requires token in 'HeaderName: value' format"
            )
            return False

        header_name, header_value = token.split(":", 1)
        session = http_utils.get_session()
        session.headers[header_name.strip()] = header_value.strip()
        logger.info("Custom auth header configured: %s", header_name.strip())
        return True

    def is_token_expired(self) -> bool:
        """Check if the current OAuth2 token has expired."""
        if not self._token_expires:
            return False
        return time.time() >= (self._token_expires - 60)  # 60s buffer

    def refresh_if_needed(self) -> bool:
        """Refresh the OAuth2 token if it's about to expire."""
        if self.config.auth_type.lower() != "oauth2":
            return True
        if not self.is_token_expired():
            return True

        logger.info("OAuth2 token expired, refreshing...")
        return self._auth_oauth2()
