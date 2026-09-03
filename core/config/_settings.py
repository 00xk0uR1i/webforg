"""webforg.core.config — centralized typed application settings.

Reads environment variables (no .env file required) with defaults that exactly
match WebForge's existing behavior. Environment variables may override defaults,
but the application must remain fully functional with none set.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

import webforg

PROJECT_DIR = Path(webforg.__file__).resolve().parent

# Environment variable names (kept stable so existing usage keeps working).
ENV = {
    "app_name": "WEBFORGE_APP_NAME",
    "version": "WEBFORGE_VERSION",
    "debug": "WEBFORGE_DEBUG",
    "host": "WEBFORGE_HOST",
    "port": "WEBFORGE_PORT",
    "data_dir": "WEBFORGE_DATA_DIR",
    "workspace_dir": "WEBFORGE_WORKSPACE_DIR",
    "cve_db_path": "WEBFORGE_CVE_DB_PATH",
    "creds_db_path": "WEBFORGE_CREDS_DB_PATH",
    "reports_dir": "WEBFORGE_REPORTS_DIR",
    "logs_dir": "WEBFORGE_LOGS_DIR",
    "certs_dir": "WEBFORGE_CERTS_DIR",
    "webui_dist_dir": "WEBFORGE_WEBUI_DIST_DIR",
    "bugbounty_dir": "WEBFORGE_BB_WORKSPACE",
    "auth_enabled": "WEBFORGE_AUTH",
    "session_ttl": "WEBFORGE_SESSION_TTL",
    "llm_api_key": "WEBFORGE_LLM_API_KEY",
    "llm_base_url": "WEBFORGE_LLM_BASE_URL",
    "llm_model": "WEBFORGE_LLM_MODEL",
    "http_timeout": "WEBFORGE_HTTP_TIMEOUT",
    "scan_timeout": "WEBFORGE_SCAN_TIMEOUT",
}


def _env_bool(name: str, default: bool) -> bool:
    val = os.environ.get(name)
    if val is None:
        return default
    return val.strip().lower() in ("1", "true", "yes", "on")


def _env_int(name: str, default: int) -> int:
    val = os.environ.get(name)
    if val is None:
        return default
    try:
        return int(val)
    except ValueError:
        return default


def _env_float(name: str, default: float) -> float:
    val = os.environ.get(name)
    if val is None:
        return default
    try:
        return float(val)
    except ValueError:
        return default


@dataclass
class AppSettings:
    """Typed application settings with env-overridable defaults.

    All defaults mirror WebForge's existing behavior exactly, so the
    application works identically when no environment variables are set.
    """

    # ── Application identity ──
    app_name: str = "WebForge"
    version: str = "0.1.0"
    debug: bool = False
    host: str = "0.0.0.0"
    port: int = 8443

    # ── Paths ──
    project_dir: Path = PROJECT_DIR
    data_dir: Path = Path.home() / ".webforg"
    workspace_dir: Path = Path.home() / ".webforg" / "workspaces"
    cve_db_path: Path = Path.home() / ".webforg" / "cve_index.db"
    creds_db_path: Path = Path.home() / ".webforg" / "creds.db"
    audit_log_path: Path = Path.home() / ".webforg" / "audit.log"
    osint_upload_dir: Path = Path.home() / ".webforg" / "osint_uploads"
    reports_dir: Path = PROJECT_DIR / "reports"
    logs_dir: Path = PROJECT_DIR / "logs"
    certs_dir: Path = PROJECT_DIR / "certs"
    webui_dist_dir: Path = PROJECT_DIR / "webui" / "dist"
    bugbounty_dir: Path = PROJECT_DIR.parent / "bugbounty"

    # ── Authentication ──
    auth_enabled: bool = True
    session_ttl: int = 8 * 3600
    login_max_fails: int = 5
    login_lock_secs: int = 60

    # ── AI / LLM ──
    llm_api_key: str = ""
    llm_base_url: str = "https://api.openai.com/v1"
    llm_model: str = "gpt-4o-mini"

    # ── Timeouts / limits ──
    http_timeout: float = 10.0
    scan_timeout: float = 1.5
    max_concurrency: int = 256

    def safe_settings(self) -> dict:
        """Return settings as a dict with all secrets redacted.

        Safe to log or render in the UI. Never exposes API keys or tokens.
        """
        return {
            "app_name": self.app_name,
            "version": self.version,
            "debug": self.debug,
            "host": self.host,
            "port": self.port,
            "project_dir": str(self.project_dir),
            "data_dir": str(self.data_dir),
            "workspace_dir": str(self.workspace_dir),
            "cve_db_path": str(self.cve_db_path),
            "creds_db_path": str(self.creds_db_path),
            "audit_log_path": str(self.audit_log_path),
            "osint_upload_dir": str(self.osint_upload_dir),
            "reports_dir": str(self.reports_dir),
            "logs_dir": str(self.logs_dir),
            "certs_dir": str(self.certs_dir),
            "webui_dist_dir": str(self.webui_dist_dir),
            "bugbounty_dir": str(self.bugbounty_dir),
            "auth_enabled": self.auth_enabled,
            "session_ttl": self.session_ttl,
            "llm_base_url": self.llm_base_url,
            "llm_model": self.llm_model,
            "llm_api_key": "[REDACTED]" if self.llm_api_key else "",
            "http_timeout": self.http_timeout,
            "scan_timeout": self.scan_timeout,
            "max_concurrency": self.max_concurrency,
        }


def _from_env() -> AppSettings:
    """Build settings from environment, preserving all current defaults."""
    home = Path.home()
    default_data_dir = home / ".webforg"

    # data_dir may be overridden; child paths follow it unless individually set.
    data_dir = Path(os.environ.get(ENV["data_dir"], str(default_data_dir)))

    workspace_dir = Path(
        os.environ.get(ENV["workspace_dir"], str(data_dir / "workspaces"))
    )
    cve_db_path = Path(os.environ.get(ENV["cve_db_path"], str(data_dir / "cve_index.db")))
    creds_db_path = Path(os.environ.get(ENV["creds_db_path"], str(data_dir / "creds.db")))

    llm_key = (
        os.environ.get("WEBFORGE_LLM_API_KEY")
        or os.environ.get("OPENAI_API_KEY")
        or ""
    )

    return AppSettings(
        app_name=os.environ.get(ENV["app_name"], "WebForge"),
        version=os.environ.get(ENV["version"], getattr(webforg, "__version__", "0.1.0")),
        debug=_env_bool(ENV["debug"], False),
        host=os.environ.get(ENV["host"], "0.0.0.0"),
        port=_env_int(ENV["port"], 8443),
        data_dir=data_dir,
        workspace_dir=workspace_dir,
        cve_db_path=cve_db_path,
        creds_db_path=creds_db_path,
        audit_log_path=data_dir / "audit.log",
        osint_upload_dir=data_dir / "osint_uploads",
        reports_dir=Path(os.environ.get(ENV["reports_dir"], str(PROJECT_DIR / "reports"))),
        logs_dir=Path(os.environ.get(ENV["logs_dir"], str(PROJECT_DIR / "logs"))),
        certs_dir=Path(os.environ.get(ENV["certs_dir"], str(PROJECT_DIR / "certs"))),
        webui_dist_dir=Path(os.environ.get(ENV["webui_dist_dir"], str(PROJECT_DIR / "webui" / "dist"))),
        bugbounty_dir=Path(
            os.environ.get(ENV["bugbounty_dir"], str(PROJECT_DIR.parent / "bugbounty"))
        ),
        auth_enabled=_env_bool(ENV["auth_enabled"], True),
        session_ttl=_env_int(ENV["session_ttl"], 8 * 3600),
        llm_api_key=llm_key,
        llm_base_url=os.environ.get(ENV["llm_base_url"], "https://api.openai.com/v1"),
        llm_model=os.environ.get(ENV["llm_model"], "gpt-4o-mini"),
        http_timeout=_env_float(ENV["http_timeout"], 10.0),
        scan_timeout=_env_float(ENV["scan_timeout"], 1.5),
    )


def get_settings() -> AppSettings:
    """Return a fresh AppSettings snapshot from the current environment.

    Re-reads environment variables on every call, so callers always see the
    latest overrides. Modules that wire settings at import time capture a
    single snapshot, matching WebForge's existing env-at-import behavior.
    """
    return _from_env()


# Convenience singleton snapshot for callers that want a stable value.
settings = _from_env()


def reload_settings() -> AppSettings:
    """Re-read the environment and refresh the module-level `settings` snapshot."""
    global settings
    settings = _from_env()
    return settings
