"""Scheduler engine — background job engine and task adapters.

Threading-based; no API/framework dependencies.  Re-exported via the legacy
``webforg.core.jobs`` and ``webforg.core.async_tasks`` facades (which share the
same job registry, so IDs/lifecycle are preserved).
"""

from __future__ import annotations

from webforg.engine.scheduler.jobs import (
    MAX_JOBS,
    Job,
    cancel,
    get,
    list_jobs,
    submit,
)
from webforg.engine.scheduler.tasks import (
    cve_update_task,
    dork_task,
    osint_scan_task,
    port_scan_task,
)

__all__ = [
    "MAX_JOBS",
    "Job",
    "cancel",
    "get",
    "list_jobs",
    "submit",
    "cve_update_task",
    "dork_task",
    "osint_scan_task",
    "port_scan_task",
]
