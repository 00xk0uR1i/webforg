"""Workspace routes for the WebForge HTTP API."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException

from webforg.core.workspace import (
    Workspace,
    _safe_workspace_name,
    delete_workspace,
    list_workspaces,
)
from webforg.apps.api.models import WorkspaceReq

router = APIRouter()


@router.get("/api/workspaces")
def api_list_workspaces():
    return {"workspaces": list_workspaces()}

@router.post("/api/workspaces/load")
def api_load_workspace(req: WorkspaceReq):
    try:
        ws = Workspace(req.name)
    except ValueError as e:
        raise HTTPException(400, str(e))
    loaded = ws.load()
    return {
        "name": ws.name,
        "loaded": loaded,
        "targets": ws.targets,
        "results": ws.results,
    }

@router.post("/api/workspaces/save")
def api_save_workspace(req: WorkspaceReq):
    try:
        ws = Workspace(req.name)
    except ValueError as e:
        raise HTTPException(400, str(e))
    ws.load()
    ws.save()
    return {"ok": True}

@router.delete("/api/workspaces/{name}")
def api_delete_workspace(name: str):
    try:
        _safe_workspace_name(name)
    except ValueError as e:
        raise HTTPException(400, str(e))
    if delete_workspace(name):
        return {"ok": True}
    raise HTTPException(404, "Workspace not found")
