"""Centralized target handling and URL parsing shared by CLI and API.

Historically both webforg/cli.py (``_normalize_url`` + inline ``urlparse``
blocks repeated ~10 times) and webforg/core/rpc_server.py (``_parse_url``)
implemented the same target->host/port/ssl/path extraction.  This service is
the single source of truth; the old helpers remain as thin compatibility
wrappers that delegate here.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional
from urllib.parse import urlparse


@dataclass(frozen=True)
class ParsedTarget:
    """A normalized web target split into module-friendly components."""

    url: str
    host: Optional[str]
    port: int
    ssl: bool
    path: str
    scheme: str
    raw_path: str = ""

    def module_options(self) -> dict:
        """Options consumed by every web module (RHOSTS/RPORT/SSL/TARGETURI)."""
        return {
            "RHOSTS": self.host,
            "RPORT": self.port,
            "SSL": self.ssl,
            "TARGETURI": self.path,
        }


class TargetService:
    """URL normalization and parsing for both front-ends."""

    @staticmethod
    def normalize_url(raw: str) -> str:
        """Ensure a URL has a scheme. Bare domains get http:// prepended.

        Preserves the exact behavior of the historical CLI ``_normalize_url``:
        strip whitespace, strip a single trailing slash, default to http://.
        """
        raw = raw.strip().rstrip("/")
        if not raw.startswith(("http://", "https://")):
            raw = f"http://{raw}"
        return raw

    @classmethod
    def parse_url(cls, url: str, default_host: Optional[str] = None) -> ParsedTarget:
        """Parse a user-supplied URL into host/port/ssl/path components.

        Matches the historical extraction used everywhere: port defaults to
        443 for https else 80, ssl is implied by the scheme, path defaults to
        "/".  When ``default_host`` is provided and the URL carries no
        hostname (the old API ``_parse_url`` behavior), it is used instead.
        """
        normalized = cls.normalize_url(url)
        parsed = urlparse(normalized)
        scheme = parsed.scheme or "http"
        host = parsed.hostname or default_host
        port = parsed.port or (443 if scheme == "https" else 80)
        ssl = scheme == "https"
        raw_path = parsed.path or ""
        path = raw_path or "/"
        return ParsedTarget(
            url=normalized,
            host=host,
            port=port,
            ssl=ssl,
            path=path,
            scheme=scheme,
            raw_path=raw_path,
        )

    @staticmethod
    def apply_to_module(module: Any, target: ParsedTarget) -> None:
        """Set RHOSTS/RPORT/SSL/TARGETURI on a module from a parsed target."""
        for name, value in target.module_options().items():
            module.set_option(name, value)
