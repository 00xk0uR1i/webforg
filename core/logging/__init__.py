"""Centralized structured logging with secret redaction.

Public API:
    get_logger(component)     — stdlib logger named ``webforg.<component>``
    configure_logging(...)    — install a root handler (idempotent)
    log_event(component, event, level, **context) — structured, redacted events
    redact / redact_text / safe_str / safe_dict / is_sensitive_key — redaction helpers
"""

from webforg.core.logging.logger import configure_logging, get_logger, log_event
from webforg.core.logging.redact import (
    REDACTED,
    is_sensitive_key,
    redact,
    redact_text,
    safe_dict,
    safe_str,
)

__all__ = [
    "REDACTED",
    "configure_logging",
    "get_logger",
    "is_sensitive_key",
    "log_event",
    "redact",
    "redact_text",
    "safe_dict",
    "safe_str",
]
