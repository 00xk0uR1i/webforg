"""Saved-credential vault routes for the WebForge HTTP API."""

from __future__ import annotations

from fastapi import APIRouter

from webforg.core.creds import (
    add_cred as creds_add,
    clear_creds as creds_clear,
    count_creds as creds_count,
    delete_cred as creds_delete,
    list_creds as creds_list,
    search_creds as creds_search,
)
from webforg.apps.api.models import CredsAddReq, CredsDeleteReq
from webforg.apps.api.shared import _audit

router = APIRouter()


@router.get("/api/creds-db/list")
def api_creds_db_list(q: str = "", limit: int = 500):
    """List (or search) saved credentials from the shared vault."""
    rows = creds_search(q, limit) if q else creds_list(limit)
    return {"creds": rows, "count": len(rows), "total": creds_count()}

@router.post("/api/creds-db/add")
def api_creds_db_add(req: CredsAddReq):
    """Manually add a credential to the vault."""
    added = creds_add(target=req.target, username=req.username, password=req.password,
                      source=req.source, extra=req.extra)
    _audit("creds_add", username=req.username, target=req.target)
    return {"success": True, "added": added, "total": creds_count()}

@router.post("/api/creds-db/delete")
def api_creds_db_delete(req: CredsDeleteReq):
    deleted = creds_delete(req.id)
    return {"success": deleted}

@router.post("/api/creds-db/clear")
def api_creds_db_clear():
    removed = creds_clear()
    _audit("creds_clear", removed=removed)
    return {"success": True, "removed": removed}
