"""Fingerprint engine — web technology analysis.

Re-exported via ``webforg.core.target`` (the Target class delegates its HTTP
fetched headers/HTML analysis here).  Pure analysis, no framework.
"""

from __future__ import annotations

from webforg.engine.fingerprint.analyzer import (
    KNOWN_FAVICON_HASHES,
    analyze_headers,
    analyze_html,
    favicon_hash,
    lookup_favicon_hash,
)

__all__ = [
    "KNOWN_FAVICON_HASHES",
    "analyze_headers",
    "analyze_html",
    "favicon_hash",
    "lookup_favicon_hash",
]
