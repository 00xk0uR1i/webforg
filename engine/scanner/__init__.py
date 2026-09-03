"""TCP port scanner engine — pure socket logic.

Re-exported by ``webforg.core.scanner`` for backward compatibility.  Callers
may import from either path; both reference the same implementation.
"""

from __future__ import annotations

from webforg.engine.scanner.tcp import (
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
