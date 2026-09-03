"""Secret redaction helpers for structured logging.

Never log passwords, API keys, tokens, cookies, private keys, or credential
material. These helpers scrub sensitive values before they reach a logger.
"""

from __future__ import annotations

import re
from typing import Any

REDACTED = "[REDACTED]"

# Substrings that mark a dict key / context field as sensitive.
SENSITIVE_KEY_MARKERS = (
    "password",
    "passwd",
    "secret",
    "token",
    "api_key",
    "apikey",
    "apikey",
    "auth",
    "authorization",
    "cookie",
    "jwt",
    "session_id",
    "session_key",
    "private_key",
    "credential",
    "llm_api_key",
    "webforg_password",
    "admin_password",
)

# Scrub `name=value` / `name: value` style secret assignments inside free text.
_SECRET_ASSIGNMENT_RE = re.compile(
    r"(?i)\b("
    r"password|passwd|secret|token|api[_-]?key|apikey|"
    r"authorization|cookie|jwt|private[_-]?key|credential|"
    r"session[_-]?id"
    r")\b\s*[=:]\s*[^\s,;\"']+"
)


def is_sensitive_key(key: str) -> bool:
    """Return True if a key name should be treated as sensitive."""
    k = (key or "").lower().replace("-", "_").strip()
    return any(marker in k for marker in SENSITIVE_KEY_MARKERS)


def redact_text(text: str) -> str:
    """Redact common secret assignments embedded in free-form text."""
    return _SECRET_ASSIGNMENT_RE.sub(lambda m: f"{m.group(1)}=******", text or "")


def redact(value: Any, key: str = "") -> Any:
    """Recursively redact sensitive values.

    Values under a sensitive key, and values that look like secrets, are
    replaced with ``[REDACTED]``.
    """
    if is_sensitive_key(key):
        return REDACTED
    if isinstance(value, dict):
        return {k: redact(v, k) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [redact(v, key) for v in value]
    if isinstance(value, str):
        if is_sensitive_key(key):
            return REDACTED
        scrubbed = redact_text(value)
        # If nothing was redacted but the string equals a bare key name,
        # leave it; otherwise return the scrubbed copy.
        return scrubbed
    return value


def safe_str(value: Any) -> str:
    """Return a string representation of a value with secrets redacted."""
    return str(redact(value))


def safe_dict(data: dict) -> dict:
    """Return a copy of a dict with all sensitive keys/values redacted."""
    return redact(data)
