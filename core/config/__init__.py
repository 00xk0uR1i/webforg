"""Centralized WebForge configuration.

Provides typed application settings with environment-variable overrides and
behavior-preserving defaults. No .env file is required.

Public API:
    AppSettings          — typed settings dataclass
    get_settings()       — fresh settings snapshot from current environment
    settings             — current module-level snapshot (updates via reload_settings)
    reload_settings()    — re-read environment into the snapshot
    ENV / PROJECT_DIR    — env var names and resolved project directory
"""

from webforg.core.config._settings import (
    ENV,
    PROJECT_DIR,
    AppSettings,
    get_settings,
)

import webforg.core.config._settings as _settings_mod

# Stable snapshot; refreshed by reload_settings().
settings = _settings_mod.settings


def reload_settings() -> AppSettings:
    """Re-read the environment and refresh the module-level `settings` snapshot."""
    global settings
    settings = _settings_mod.reload_settings()
    return settings


__all__ = [
    "ENV",
    "PROJECT_DIR",
    "AppSettings",
    "get_settings",
    "reload_settings",
    "settings",
]
