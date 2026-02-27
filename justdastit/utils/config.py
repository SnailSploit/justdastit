"""justdastit - YAML configuration loader with CLI override support."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Optional

from ..core.models import ProjectConfig, ScopeRule

__all__ = ["load_config", "generate_default_config", "CONFIG_FILENAME"]

CONFIG_FILENAME = "justdastit.yaml"

DEFAULT_CONFIG = """\
# justdastit project configuration
# Docs: https://github.com/snailsploit/justdastit

project: my-target

scope:
  include:
    - "*.target.com"
  exclude:
    - "logout"
    - "delete"
    - "signout"

# auth:
#   type: bearer          # bearer | basic | header
#   token: "eyJ..."       # for bearer
#   username: "admin"     # for basic
#   password: "pass"      # for basic
#   header: "X-API-Key"   # for header
#   value: "key123"       # for header

scanner:
  threads: 10
  timeout: 10.0
  delay_ms: 0
  max_depth: 5
  user_agent: "justdastit/3.0"
  follow_redirects: true
  verify_ssl: false

proxy:
  host: "127.0.0.1"
  port: 8080
  # upstream: "http://127.0.0.1:8888"

database:
  path: "justdastit.db"
"""


def _load_yaml(path: Path) -> dict[str, Any]:
    """Load YAML file, gracefully falling back if pyyaml not installed."""
    try:
        import yaml
    except ImportError:
        raise ImportError(
            "pyyaml is required for config file support. "
            "Install with: pip install justdastit[config]"
        )
    with open(path) as f:
        return yaml.safe_load(f) or {}


def load_config(
    config_path: Optional[str] = None,
    cli_overrides: Optional[dict[str, Any]] = None,
) -> ProjectConfig:
    """Load config from YAML file with CLI overrides.

    Priority: CLI flags > config file > defaults
    """
    data: dict[str, Any] = {}

    # Auto-detect config in CWD
    if config_path is None:
        cwd_config = Path.cwd() / CONFIG_FILENAME
        if cwd_config.exists():
            config_path = str(cwd_config)

    if config_path and Path(config_path).exists():
        data = _load_yaml(Path(config_path))

    # Build ProjectConfig
    scanner_cfg = data.get("scanner", {})
    proxy_cfg = data.get("proxy", {})
    db_cfg = data.get("database", {})
    scope_cfg = data.get("scope", {})
    auth_cfg = data.get("auth", {})

    config = ProjectConfig(
        name=data.get("project", "default"),
        db_path=db_cfg.get("path", "justdastit.db"),
        proxy_port=proxy_cfg.get("port", 8080),
        proxy_host=proxy_cfg.get("host", "127.0.0.1"),
        threads=scanner_cfg.get("threads", 10),
        timeout=scanner_cfg.get("timeout", 10.0),
        user_agent=scanner_cfg.get("user_agent", "justdastit/3.0"),
        follow_redirects=scanner_cfg.get("follow_redirects", True),
        max_depth=scanner_cfg.get("max_depth", 5),
        verify_ssl=scanner_cfg.get("verify_ssl", False),
        delay_ms=scanner_cfg.get("delay_ms", 0.0),
    )

    # Scope
    if scope_cfg:
        config.scope = ScopeRule(
            include_patterns=scope_cfg.get("include", []),
            exclude_patterns=scope_cfg.get("exclude", []),
        )

    # Auth
    if auth_cfg:
        auth_type = auth_cfg.get("type", "")
        config.auth_type = auth_type
        if auth_type == "bearer":
            config.auth_value = auth_cfg.get("token", "")
        elif auth_type == "basic":
            config.auth_value = f"{auth_cfg.get('username', '')}:{auth_cfg.get('password', '')}"
        elif auth_type == "header":
            config.auth_value = f"{auth_cfg.get('header', '')}:{auth_cfg.get('value', '')}"

    # CLI overrides
    if cli_overrides:
        for key, value in cli_overrides.items():
            if value is not None and hasattr(config, key):
                setattr(config, key, value)

    return config


def generate_default_config(output_path: Optional[str] = None) -> str:
    """Generate a default configuration file."""
    path = output_path or CONFIG_FILENAME
    Path(path).write_text(DEFAULT_CONFIG)
    return path
