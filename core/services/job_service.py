"""Framework-agnostic job service (Phase 8).

Wraps the Phase 6 async job engine (``webforg.engine.scheduler.jobs``) behind a
service boundary so FastAPI routes and the CLI share one consistent view of job
lifecycle, progress and results without owning job business logic.

The engine remains the single source of truth for execution: it runs each job
on a background daemon thread and passes a ``progress(percent, message)``
callable into the task.  This service only owns:

  * the action registry (action name -> callable + default params),
  * parameter whitelisting (only keys present in an action's defaults pass),
  * the thin submit/get/list/cancel facade.

No FastAPI/Starlette imports here — callers own HTTP semantics.
"""

from __future__ import annotations

from typing import Any, Callable, Optional

from webforg.engine.scheduler.jobs import (
    cancel as _cancel,
    get as _get,
    list_jobs as _list,
    submit as _submit,
)
from webforg.engine.scheduler.tasks import (
    cve_update_task,
    dork_task,
    osint_scan_task,
    port_scan_task,
)

def _scan_url_task(url: str, checks: str = "all", threads: Optional[int] = None,
                   default_host: str = "127.0.0.1", progress: Optional[callable] = None) -> dict:
    """Job-friendly wrapper for the multi-handler web scan (additive action).

    Lazily imports ScanService to keep the scheduler engine free of service
    imports at module load time (ScanService itself depends on the engine).
    """
    from webforg.core.services.scan_service import ScanService
    if progress:
        progress(5, "Starting web scan")
    result = ScanService().scan_url(
        url, checks=checks, threads=threads, default_host=default_host or None,
    )
    if progress:
        progress(100, "Scan complete")
    return result


# Action registry: action name -> (callable, default params dict).
# Only params present in an action's defaults are accepted (whitelist).
_ACTIONS: dict[str, tuple[Callable, dict]] = {
    "portscan": (
        port_scan_task,
        {"host": "", "ports": "common", "timeout": 1.5, "workers": 64,
         "grab_banners": True, "use_ssl": False},
    ),
    "osint": (
        osint_scan_task,
        {"query": "", "mode": "username", "categories": None, "workers": 12},
    ),
    "dork": (
        dork_task,
        {"query": "", "engine": "ddg", "limit": 20, "target": ""},
    ),
    "cve_update": (
        cve_update_task,
        {"nvd_days": 90, "sploitus_pages": 5},
    ),
    "scan_url": (
        _scan_url_task,
        {"url": "", "checks": "all", "threads": None, "default_host": "127.0.0.1"},
    ),
}


class JobService:
    """Service boundary over the async job engine."""

    def __init__(self, actions: Optional[dict[str, tuple[Callable, dict]]] = None):
        self._actions = dict(actions) if actions is not None else dict(_ACTIONS)

    # ── registry discovery ──

    def actions(self) -> list[str]:
        """Sorted action names this service can run."""
        return sorted(self._actions)

    def has_action(self, action: str) -> bool:
        return action in self._actions

    def action_defaults(self, action: str) -> dict:
        """Default params for an action (raises KeyError if unknown)."""
        return dict(self._actions[action][1])

    # ── submission ──

    def submit(self, action: str, params: Optional[dict] = None) -> str:
        """Submit a background job and return its job id.

        Raises ``ValueError`` for unknown actions.  Only keys present in the
        action's defaults are forwarded (whitelist) — unknown params are
        silently ignored, mirroring the historical API behavior.
        """
        if action not in self._actions:
            raise ValueError(f"Unknown action '{action}'")
        fn, defaults = self._actions[action]
        merged = dict(defaults)
        for key, value in (params or {}).items():
            if key in defaults:
                merged[key] = value
        return _submit(action, fn, **merged)

    # ── lifecycle / status ──

    def get(self, job_id: str, include_result: bool = False) -> Optional[dict]:
        """Job status dict, or None when unknown."""
        job = _get(job_id)
        if job is None:
            return None
        return job.to_dict(include_result=include_result)

    def list(self, limit: int = 20) -> list[dict]:
        """Recent jobs, newest first, without results."""
        return _list(limit=limit)

    def cancel(self, job_id: str) -> bool:
        """Request cancellation; False when the job is unknown."""
        return _cancel(job_id)
