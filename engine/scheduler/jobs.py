"""Async job engine — run long operations in background threads with progress polling.

Real implementation migrated from ``webforg.core.jobs`` (Phase 6).  The legacy
path remains a compatibility facade re-exporting from here, sharing the same
module-level job registry so job IDs and lifecycle are unchanged.
"""

from __future__ import annotations

import threading
import time
import uuid
from typing import Callable, Optional

from webforg.core.logging import log_event

MAX_JOBS = 50


class Job:
    __slots__ = ("id", "name", "status", "progress", "message", "result", "error",
                 "created_at", "updated_at", "fn", "args", "kwargs", "thread", "cancelled")

    def __init__(self, job_id: str, name: str, fn: Callable, args: tuple, kwargs: dict):
        self.id = job_id
        self.name = name
        self.status = "queued"
        self.progress = 0
        self.message = "Queued"
        self.result = None
        self.error = None
        self.created_at = time.time()
        self.updated_at = time.time()
        self.fn = fn
        self.args = args
        self.kwargs = kwargs
        self.thread: Optional[threading.Thread] = None
        self.cancelled = False

    def set_progress(self, progress: int, message: str = "") -> None:
        self.progress = max(0, min(100, int(progress)))
        if message:
            self.message = message
        self.updated_at = time.time()

    def to_dict(self, include_result: bool = True) -> dict:
        d = {
            "id": self.id,
            "name": self.name,
            "status": self.status,
            "progress": self.progress,
            "message": self.message,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "cancelled": self.cancelled,
        }
        if include_result and self.status == "done":
            d["result"] = self.result
        if self.error:
            d["error"] = self.error
        return d


_lock = threading.Lock()
_jobs: dict[str, Job] = {}


def _run(job: Job) -> None:
    job.status = "running"
    job.thread = threading.current_thread()
    job.set_progress(0, "Running")
    log_event("jobs", "started", job_id=job.id, name=job.name)
    try:
        result = job.fn(*job.args, progress=job.set_progress, **job.kwargs)
        if job.cancelled:
            job.status = "cancelled"
            job.set_progress(0, "Cancelled")
            log_event("jobs", "cancelled", job_id=job.id, name=job.name)
        else:
            job.result = result
            job.status = "done"
            job.set_progress(100, "Complete")
            log_event("jobs", "done", job_id=job.id, name=job.name)
    except Exception as e:
        job.error = str(e)
        job.status = "error"
        job.set_progress(0, f"Error: {e}")
        log_event("jobs", "error", job_id=job.id, name=job.name, error=str(e))
    finally:
        job.updated_at = time.time()


def submit(name: str, fn: Callable, *args, **kwargs) -> str:
    """Start a background job. The fn receives a `progress(percent, message)` callable as a keyword arg."""
    job_id = uuid.uuid4().hex[:12]
    job = Job(job_id, name, fn, args, kwargs)
    with _lock:
        _jobs[job_id] = job
        # Trim old finished jobs beyond cap.
        if len(_jobs) > MAX_JOBS:
            for jid in [k for k, v in _jobs.items() if v.status in ("done", "error", "cancelled")]:
                _jobs.pop(jid, None)
                if len(_jobs) <= MAX_JOBS:
                    break
    t = threading.Thread(target=_run, args=(job,), daemon=True, name=f"job-{job_id}")
    t.start()
    log_event("jobs", "submitted", job_id=job_id, name=name)
    return job_id


def get(job_id: str) -> Optional[Job]:
    return _jobs.get(job_id)


def list_jobs(limit: int = 20) -> list[dict]:
    jobs = sorted(_jobs.values(), key=lambda j: j.created_at, reverse=True)
    return [j.to_dict(include_result=False) for j in jobs[:limit]]


def cancel(job_id: str) -> bool:
    job = _jobs.get(job_id)
    if not job:
        return False
    job.cancelled = True
    if job.status == "queued":
        job.status = "cancelled"
    elif job.status == "running":
        job.status = "cancelling"
    log_event("jobs", "cancel_requested", job_id=job_id, name=job.name)
    return True
