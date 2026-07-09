from __future__ import annotations
"""
scanner/config.py
------------------
Enterprise configuration management for W3BSP1D3R.

Supports:
  - YAML config files with profile-based overrides (quick/standard/thorough)
  - Environment variable expansion for secrets (${VAR_NAME} syntax)
  - Scan scope control (include/exclude URL patterns)
  - Policy enforcement (minimum delay, max threads, required scan types)
  - Sensible defaults for everything — no config file required

Usage:
    from scanner.config import ScanConfig, load_config

    # Load from YAML file
    config = load_config("w3bsp1d3r.yaml", profile="thorough")

    # Or build programmatically
    config = ScanConfig(url="http://localhost/dvwa")
"""

import logging
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger(__name__)

# Environment variable pattern: ${VAR_NAME} or ${VAR_NAME:-default}
_ENV_PATTERN = re.compile(r"\$\{([^}:]+)(?::-(.*?))?\}")


def _expand_env_vars(value: Any) -> Any:
    """Recursively expand ${VAR} and ${VAR:-default} in strings."""
    if isinstance(value, str):
        def _replacer(m: re.Match) -> str:
            var_name = m.group(1)
            default = m.group(2) if m.group(2) is not None else ""
            return os.environ.get(var_name, default)
        return _ENV_PATTERN.sub(_replacer, value)
    if isinstance(value, dict):
        return {k: _expand_env_vars(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_expand_env_vars(item) for item in value]
    return value


# ---------------------------------------------------------------------------
# Scope control
# ---------------------------------------------------------------------------

@dataclass
class ScopeConfig:
    """URL scope include/exclude patterns (fnmatch-style globs)."""
    include: list[str] = field(default_factory=list)
    exclude: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Rate limiting config
# ---------------------------------------------------------------------------

@dataclass
class RateLimitConfig:
    """Controls retry behaviour and adaptive rate limiting."""
    adaptive: bool = True
    max_retries: int = 3
    backoff_factor: float = 2.0
    retry_on_status: list[int] = field(default_factory=lambda: [429, 500, 502, 503, 504])
    max_backoff: float = 60.0


# ---------------------------------------------------------------------------
# Policy enforcement
# ---------------------------------------------------------------------------

@dataclass
class PolicyConfig:
    """Enterprise policy constraints applied after all other config."""
    min_delay: float = 0.0
    max_threads: int = 128
    required_scan_types: list[str] = field(default_factory=list)
    fail_on: Optional[str] = None


# ---------------------------------------------------------------------------
# Checkpoint config
# ---------------------------------------------------------------------------

@dataclass
class CheckpointConfig:
    """Scan checkpoint/resume settings."""
    enabled: bool = False
    directory: str = ".w3bsp1d3r/checkpoints"


# ---------------------------------------------------------------------------
# Audit config
# ---------------------------------------------------------------------------

@dataclass
class AuditConfig:
    """Audit trail settings."""
    enabled: bool = False
    log_file: str = ".w3bsp1d3r/audit.log"


# ---------------------------------------------------------------------------
# Database config
# ---------------------------------------------------------------------------

@dataclass
class DatabaseConfig:
    """Historical scan database settings."""
    enabled: bool = False
    path: str = ".w3bsp1d3r/scans.db"


# ---------------------------------------------------------------------------
# Auth config
# ---------------------------------------------------------------------------

@dataclass
class AuthConfig:
    """Authentication configuration."""
    auth_type: str = "none"  # none | form | bearer | oauth2 | ntlm
    username: Optional[str] = None
    password: Optional[str] = None
    token: Optional[str] = None
    # OAuth2
    oauth2_token_url: Optional[str] = None
    oauth2_client_id: Optional[str] = None
    oauth2_client_secret: Optional[str] = None
    oauth2_scope: Optional[str] = None
    # NTLM
    ntlm_domain: Optional[str] = None


# ---------------------------------------------------------------------------
# Logging config
# ---------------------------------------------------------------------------

@dataclass
class LoggingConfig:
    """Structured logging settings."""
    level: str = "WARNING"
    format: str = "text"  # text | json
    file: Optional[str] = None
    include_request_id: bool = True


# ---------------------------------------------------------------------------
# Webhook config
# ---------------------------------------------------------------------------

@dataclass
class WebhookConfig:
    """Webhook notification settings."""
    enabled: bool = False
    slack_url: Optional[str] = None
    teams_url: Optional[str] = None
    discord_url: Optional[str] = None
    generic_urls: list[str] = field(default_factory=list)
    timeout: int = 15
    on_findings_only: bool = False


# ---------------------------------------------------------------------------
# Plugin config
# ---------------------------------------------------------------------------

@dataclass
class PluginConfig:
    """Plugin system settings."""
    enabled: bool = False
    directories: list[str] = field(default_factory=lambda: ["plugins"])


# ---------------------------------------------------------------------------
# Main ScanConfig
# ---------------------------------------------------------------------------

@dataclass
class ScanConfig:
    """
    Complete scan configuration — the single source of truth.

    All scanner components read from this object. It can be built from:
      - YAML file (load_config)
      - CLI arguments (from_cli_args)
      - Programmatic construction
    """
    # Target
    url: str = ""
    scan_type: str = "full"

    # Scan parameters
    threads: int = 4
    max_pages: int = 50
    delay: float = 0.5
    timeout: int = 10
    verify_ssl: bool = True
    proxy: Optional[str] = None

    # Output
    output: str = "scan_report"
    output_formats: list[str] = field(
        default_factory=lambda: ["html", "md", "json", "sarif"]
    )
    verbose: bool = False

    # Integrations
    vt_api_key: Optional[str] = None
    vt_delay: float = 15.0
    nvd_api_key: Optional[str] = None

    # Sub-configs
    auth: AuthConfig = field(default_factory=AuthConfig)
    scope: ScopeConfig = field(default_factory=ScopeConfig)
    rate_limit: RateLimitConfig = field(default_factory=RateLimitConfig)
    policy: PolicyConfig = field(default_factory=PolicyConfig)
    checkpoint: CheckpointConfig = field(default_factory=CheckpointConfig)
    audit: AuditConfig = field(default_factory=AuditConfig)
    database: DatabaseConfig = field(default_factory=DatabaseConfig)
    logging: LoggingConfig = field(default_factory=LoggingConfig)
    plugins: PluginConfig = field(default_factory=PluginConfig)
    webhooks: WebhookConfig = field(default_factory=WebhookConfig)

    # UI
    dashboard: bool = False

    # CI/CD
    fail_on: Optional[str] = None

    # Compare
    compare_with: Optional[str] = None

    # Resume a previously interrupted scan from its checkpoint
    resume: bool = False

    # Render pages in a headless browser (JS/SPA crawling + DOM XSS)
    render: bool = False

    # Drive safe SPA interactions (search, form submit, safe clicks) so injectable
    # XHR/fetch endpoints fire and get captured (Phase E). Implies render.
    interact: bool = False

    def apply_policies(self) -> list[str]:
        """
        Enforce enterprise policies. Returns list of warning messages
        for any values that were clamped.
        """
        warnings = []

        if self.delay < self.policy.min_delay:
            warnings.append(
                f"Policy: delay raised from {self.delay}s to "
                f"{self.policy.min_delay}s (minimum enforced)"
            )
            self.delay = self.policy.min_delay

        if self.threads > self.policy.max_threads:
            warnings.append(
                f"Policy: threads capped from {self.threads} to "
                f"{self.policy.max_threads} (maximum enforced)"
            )
            self.threads = self.policy.max_threads

        if self.policy.fail_on and not self.fail_on:
            self.fail_on = self.policy.fail_on
            warnings.append(
                f"Policy: --fail-on set to '{self.policy.fail_on}' by policy"
            )

        return warnings


# ---------------------------------------------------------------------------
# Scan profiles — predefined configurations
# ---------------------------------------------------------------------------

_PROFILES: dict[str, dict[str, Any]] = {
    "quick": {
        "threads": 2,
        "max_pages": 10,
        "delay": 0.2,
        "timeout": 5,
    },
    "standard": {
        "threads": 4,
        "max_pages": 50,
        "delay": 0.5,
        "timeout": 10,
    },
    "thorough": {
        "threads": 8,
        "max_pages": 500,
        "delay": 1.0,
        "timeout": 30,
    },
    "stealth": {
        "threads": 1,
        "max_pages": 30,
        "delay": 3.0,
        "timeout": 15,
    },
}


def _apply_profile(config: ScanConfig, profile_name: str) -> None:
    """Apply a named scan profile to the config."""
    if profile_name not in _PROFILES:
        raise ValueError(
            f"Unknown profile '{profile_name}'. "
            f"Available: {', '.join(_PROFILES.keys())}"
        )
    profile = _PROFILES[profile_name]
    for key, value in profile.items():
        if hasattr(config, key):
            setattr(config, key, value)
    logger.info("Applied scan profile: %s", profile_name)


# ---------------------------------------------------------------------------
# YAML config loading
# ---------------------------------------------------------------------------

def _set_nested(obj: Any, key: str, value: Any) -> None:
    """Set a possibly dotted key on a dataclass hierarchy."""
    parts = key.split(".", 1)
    if len(parts) == 1:
        if hasattr(obj, parts[0]):
            setattr(obj, parts[0], value)
    else:
        sub_obj = getattr(obj, parts[0], None)
        if sub_obj is not None:
            _set_nested(sub_obj, parts[1], value)


def _populate_dataclass(obj: Any, data: dict, prefix: str = "") -> None:
    """Recursively populate a dataclass from a dict."""
    for key, value in data.items():
        if hasattr(obj, key):
            attr = getattr(obj, key)
            if hasattr(attr, "__dataclass_fields__") and isinstance(value, dict):
                _populate_dataclass(attr, value)
            else:
                setattr(obj, key, value)


def load_config(
    path: str | Path,
    profile: str | None = None,
    cli_overrides: dict[str, Any] | None = None,
) -> ScanConfig:
    """
    Load scan configuration from a YAML file.

    Priority (highest to lowest):
      1. CLI overrides
      2. YAML file values
      3. Profile defaults
      4. ScanConfig defaults

    Environment variables are expanded in all string values.
    """
    try:
        import yaml
    except ImportError:
        raise ImportError(
            "PyYAML is required for config file support. "
            "Install with: pip install pyyaml"
        )

    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"Config file not found: {path}")

    with path.open("r", encoding="utf-8") as fh:
        raw = yaml.safe_load(fh)

    if not isinstance(raw, dict):
        raise ValueError(f"Config file must be a YAML mapping, got {type(raw).__name__}")

    # Expand environment variables in all string values
    raw = _expand_env_vars(raw)

    config = ScanConfig()

    # Apply profile first (lowest priority after defaults)
    profile_name = profile or raw.get("profile")
    if profile_name:
        _apply_profile(config, profile_name)

    # Apply YAML values
    # Handle top-level target section
    if "target" in raw:
        target = raw["target"]
        if "url" in target:
            config.url = target["url"]
        if "scope" in target:
            _populate_dataclass(config.scope, target["scope"])

    # Handle top-level sections that map to sub-configs
    section_map = {
        "auth": config.auth,
        "rate_limiting": config.rate_limit,
        "policies": config.policy,
        "checkpoint": config.checkpoint,
        "audit": config.audit,
        "database": config.database,
        "logging": config.logging,
        "plugins": config.plugins,
        "webhooks": config.webhooks,
        "scope": config.scope,
    }
    for section_name, sub_obj in section_map.items():
        if section_name in raw and isinstance(raw[section_name], dict):
            _populate_dataclass(sub_obj, raw[section_name])

    # Handle scan section
    if "scan" in raw:
        scan = raw["scan"]
        for key in ("type", "scan_type"):
            if key in scan:
                config.scan_type = scan[key]
        for key in ("threads", "max_pages", "delay", "timeout", "verify_ssl"):
            if key in scan:
                setattr(config, key, scan[key])

    # Handle output section
    if "output" in raw:
        out = raw["output"]
        if isinstance(out, str):
            config.output = out
        elif isinstance(out, dict):
            if "base_filename" in out:
                config.output = out["base_filename"]
            if "formats" in out:
                config.output_formats = out["formats"]

    # Handle integrations
    if "integrations" in raw:
        intg = raw["integrations"]
        if "virustotal" in intg:
            vt = intg["virustotal"]
            config.vt_api_key = vt.get("api_key") or config.vt_api_key
            config.vt_delay = vt.get("delay", config.vt_delay)
        if "nvd" in intg:
            config.nvd_api_key = intg["nvd"].get("api_key") or config.nvd_api_key
        if "proxy" in intg:
            config.proxy = intg["proxy"]

    # Direct top-level keys (excludes 'output' — handled by output section above)
    for key in ("url", "scan_type", "threads", "max_pages", "delay", "timeout",
                "verify_ssl", "proxy", "verbose", "fail_on", "dashboard",
                "vt_api_key", "nvd_api_key", "compare_with"):
        if key in raw:
            setattr(config, key, raw[key])

    # Apply CLI overrides (highest priority)
    if cli_overrides:
        for key, value in cli_overrides.items():
            if value is not None and hasattr(config, key):
                setattr(config, key, value)

    # Apply enterprise policies
    policy_warnings = config.apply_policies()
    for w in policy_warnings:
        logger.warning(w)

    return config


def load_config_from_env() -> dict[str, Any]:
    """
    Load configuration values from environment variables.

    Supported variables:
      W3BSP1D3R_URL           - Target URL
      W3BSP1D3R_SCAN_TYPE     - Scan type
      W3BSP1D3R_THREADS       - Thread count
      W3BSP1D3R_DELAY         - Request delay
      W3BSP1D3R_VT_API_KEY    - VirusTotal API key
      W3BSP1D3R_NVD_API_KEY   - NVD API key
      W3BSP1D3R_PROXY         - Proxy URL
      W3BSP1D3R_AUTH_TOKEN    - Bearer/JWT token
      W3BSP1D3R_LOGIN_USER    - Login username
      W3BSP1D3R_LOGIN_PASS    - Login password
      W3BSP1D3R_FAIL_ON       - CI/CD failure threshold
      W3BSP1D3R_OUTPUT        - Report base filename
    """
    env_map = {
        "W3BSP1D3R_URL": ("url", str),
        "W3BSP1D3R_SCAN_TYPE": ("scan_type", str),
        "W3BSP1D3R_THREADS": ("threads", int),
        "W3BSP1D3R_DELAY": ("delay", float),
        "W3BSP1D3R_TIMEOUT": ("timeout", int),
        "W3BSP1D3R_VT_API_KEY": ("vt_api_key", str),
        "W3BSP1D3R_NVD_API_KEY": ("nvd_api_key", str),
        "W3BSP1D3R_PROXY": ("proxy", str),
        "W3BSP1D3R_AUTH_TOKEN": ("auth_token", str),
        "W3BSP1D3R_LOGIN_USER": ("login_user", str),
        "W3BSP1D3R_LOGIN_PASS": ("login_pass", str),
        "W3BSP1D3R_FAIL_ON": ("fail_on", str),
        "W3BSP1D3R_OUTPUT": ("output", str),
    }

    overrides: dict[str, Any] = {}
    for env_var, (config_key, cast_fn) in env_map.items():
        val = os.environ.get(env_var)
        if val is not None:
            try:
                overrides[config_key] = cast_fn(val)
            except (ValueError, TypeError):
                logger.warning("Invalid value for %s: %s", env_var, val)

    return overrides


def get_available_profiles() -> dict[str, dict[str, Any]]:
    """Return the available scan profile names and their settings."""
    return dict(_PROFILES)
