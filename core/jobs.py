"""Async job engine — compatibility facade (Phase 6).

The real implementation lives in :mod:`webforg.engine.scheduler.jobs`.  This
module re-exports it so existing callers keep working; both paths share the
same module-level job registry, preserving job IDs and lifecycle.
"""

from __future__ import annotations

from webforg.engine.scheduler.jobs import (  # noqa: F401
    MAX_JOBS,
    Job,
    cancel,
    get,
    list_jobs,
    submit,
)

__all__ = [
    "MAX_JOBS",
    "Job",
    "cancel",
    "get",
    "list_jobs",
    "submit",
]
