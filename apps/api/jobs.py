"""Async job-engine routes for the WebForge HTTP API."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request

from webforg.apps.api.models import JobSubmitReq
from webforg.apps.api.shared import _audit, _client_ip, _get_job_service

router = APIRouter()


@router.post("/api/jobs/submit")
def api_job_submit(req: JobSubmitReq, request: Request):
    """Submit a long-running task to run in the background."""
    try:
        job_id = _get_job_service().submit(req.action, req.params or {})
    except ValueError as e:
        raise HTTPException(400, str(e))
    _audit("job_submit", ip=_client_ip(request), action_name=req.action, job_id=job_id)
    return {"job_id": job_id, "action": req.action}

@router.get("/api/jobs")
def api_job_list():
    return {"jobs": _get_job_service().list()}

@router.get("/api/jobs/{job_id}")
def api_job_status(job_id: str, include_result: bool = False):
    job = _get_job_service().get(job_id, include_result=include_result)
    if job is None:
        raise HTTPException(404, "Job not found")
    return job

@router.post("/api/jobs/{job_id}/cancel")
def api_job_cancel(job_id: str):
    ok = _get_job_service().cancel(job_id)
    if not ok:
        raise HTTPException(404, "Job not found")
    return {"success": True}
