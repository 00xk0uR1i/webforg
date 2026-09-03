"""Structured, contextual logging for WebForge components.

Loggers are stdlib ``logging.Logger`` instances named ``webforg.<component>``.
Context fields (job ID, target, component, event, ...) are redacted before they
reach the handler so secrets never get logged.
"""

from __future__ import annotations

import logging as _logging
import sys
from typing import Optional

from webforg.core.logging.redact import redact

_FORMAT = "%(asctime)s | %(levelname)-7s | %(name)s | %(message)s"


def get_logger(component: str) -> _logging.Logger:
    """Return the stdlib logger for a component (``webforg.<component>``)."""
    return _logging.getLogger(f"webforg.{component}")


def configure_logging(
    level: int = _logging.INFO,
    stream=None,
    fmt: Optional[str] = None,
    force: bool = False,
) -> None:
    """Attach a handler to the ``webforg`` logger for structured logs.

    Idempotent: repeated calls do not stack duplicate handlers (unless
    ``force=True`` is used). The handler is attached to the ``webforg``
    logger with propagation disabled so it never interferes with uvicorn's
    or other frameworks' logging configuration.
    """
    if stream is None:
        stream = sys.stderr
    wf_logger = _logging.getLogger("webforg")
    if force:
        wf_logger.handlers.clear()
    if not any(
        getattr(h, "_webforge_handler", False) for h in wf_logger.handlers
    ):
        handler = _logging.StreamHandler(stream)
        handler.setFormatter(_logging.Formatter(fmt or _FORMAT))
        handler._webforge_handler = True  # type: ignore[attr-defined]
        wf_logger.addHandler(handler)
    wf_logger.setLevel(level)
    wf_logger.propagate = False


def log_event(
    component: str,
    event: str,
    level: int = _logging.INFO,
    **context,
) -> None:
    """Log a structured event with redacted context.

    Example:
        log_event("api", "startup", host="0.0.0.0", port=8443)
    """
    logger = get_logger(component)
    ctx = redact(context)
    parts = [f"event={event}"]
    parts.extend(f"{k}={v!r}" for k, v in ctx.items())
    logger.log(level, " ".join(parts))
