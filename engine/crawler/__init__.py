"""Crawler engine — HTML form and link extraction.

Re-exported via the ``form_crawler`` module wrappers; callers may import from
either path.  Pure parsing logic, no network or framework dependencies.
"""

from __future__ import annotations

from webforg.engine.crawler.html import (
    COMMON_LOGIN_PATHS,
    LoginForm,
    extract_forms,
    extract_links,
    is_same_domain,
)

__all__ = [
    "COMMON_LOGIN_PATHS",
    "LoginForm",
    "extract_forms",
    "extract_links",
    "is_same_domain",
]
