"""TCP port scanner — compatibility facade (Phase 6).

The real implementation lives in :mod:`webforg.engine.scanner`.  This module
re-exports it so existing callers (``from webforg.core.scanner import scan``)
keep working unchanged.
"""

from __future__ import annotations

from webforg.engine.scanner.tcp import (  # noqa: F401
    COMMON_PORTS,
    DEFAULT_TIMEOUT,
    MAX_CONCURRENCY,
    PORT_SERVICES,
    PortResult,
    ScanOptions,
    _BANNER_HINTS,
    _banner_grab,
    _probe,
    _service_from_banner,
    parse_ports,
    scan,
)

__all__ = [
    "COMMON_PORTS",
    "DEFAULT_TIMEOUT",
    "MAX_CONCURRENCY",
    "PORT_SERVICES",
    "PortResult",
    "ScanOptions",
    "parse_ports",
    "scan",
]
