"""Async task wrappers — compatibility facade (Phase 6).

The real implementation lives in :mod:`webforg.engine.scheduler.tasks`.  This
module re-exports it so existing callers (``from webforg.core.async_tasks
import port_scan_task``) keep working unchanged.
"""

from __future__ import annotations

from webforg.engine.scheduler.tasks import (  # noqa: F401
    cve_update_task,
    dork_task,
    osint_scan_task,
    port_scan_task,
)

__all__ = [
    "cve_update_task",
    "dork_task",
    "osint_scan_task",
    "port_scan_task",
]
