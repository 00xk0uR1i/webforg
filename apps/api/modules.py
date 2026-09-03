"""Module management and dashboard routes for the WebForge HTTP API."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException

from webforg.core.cve_db import get_sploitus_stats
from webforg.core.module import BaseAuxiliaryModule, BaseExploitModule
from webforg.core.session import sessions
from webforg.core.top10 import get_top10
from webforg.apps.api.models import RunModuleReq, SetOptionReq
from webforg.apps.api.shared import _audit, _module_service

router = APIRouter()


@router.get("/api/modules")
def api_list_modules():
    return {"modules": _module_service.list_metadata()}

@router.get("/api/modules/{module_path:path}")
def api_get_module(module_path: str):
    try:
        inst = _get_or_create_module(module_path)
    except HTTPException:
        raise

    info = _module_service.metadata(module_path, inst)
    info["options"] = _module_service.option_descriptors(inst)
    return info

def _get_or_create_module(module_path: str) -> BaseModule:
    """Get a cached module instance or create a new one (via ModuleService)."""
    inst = _module_service.get_or_create(module_path)
    if inst is None:
        raise HTTPException(404, "Module not found")
    return inst

@router.post("/api/modules/set-option")
def api_set_option(req: SetOptionReq):
    try:
        inst = _get_or_create_module(req.module_path)
    except HTTPException:
        raise
    try:
        _module_service.set_option(inst, req.name.upper(), req.value)
    except KeyError as e:
        raise HTTPException(400, str(e))
    return {"ok": True}

@router.post("/api/modules/check")
def api_check(req: RunModuleReq):
    try:
        inst = _get_or_create_module(req.module_path)
    except HTTPException:
        raise
    if not isinstance(inst, BaseExploitModule):
        raise HTTPException(400, "Module is not an exploit module")

    errors = _module_service.validate(inst)
    if errors:
        raise HTTPException(400, "; ".join(errors))

    try:
        result = _module_service.check(inst)
        _audit("module_check", module=req.module_path)
        return {"vulnerable": result.vulnerable, "details": result.details}
    except Exception as e:
        _audit("module_check_error", module=req.module_path, error=str(e)[:200])
        raise HTTPException(500, f"Internal error: {type(e).__name__}")

@router.post("/api/modules/exploit")
def api_exploit(req: RunModuleReq):
    try:
        inst = _get_or_create_module(req.module_path)
    except HTTPException:
        raise
    if not isinstance(inst, BaseExploitModule):
        raise HTTPException(400, "Module is not an exploit module")

    errors = _module_service.validate(inst)
    if errors:
        raise HTTPException(400, "; ".join(errors))

    try:
        result = _module_service.exploit(inst)
        _audit("module_exploit", module=req.module_path)
        return {
            "success": result.success,
            "output": result.output,
            "session_id": result.session_id,
        }
    except Exception as e:
        _audit("module_exploit_error", module=req.module_path, error=str(e)[:200])
        raise HTTPException(500, f"Internal error: {type(e).__name__}")

@router.post("/api/modules/run")
def api_run_auxiliary(req: RunModuleReq):
    try:
        inst = _get_or_create_module(req.module_path)
    except HTTPException:
        raise
    if not isinstance(inst, BaseAuxiliaryModule):
        raise HTTPException(400, "Module is not an auxiliary module")

    errors = _module_service.validate(inst)
    if errors:
        raise HTTPException(400, "; ".join(errors))

    try:
        result = _module_service.run(inst)
        _audit("module_run", module=req.module_path)
        return result
    except Exception as e:
        _audit("module_run_error", module=req.module_path, error=str(e)[:200])
        raise HTTPException(500, f"Internal error: {type(e).__name__}")

@router.get("/api/logo")
def api_logo():
    from webforg.core.theme import SKULL_LOGO
    return {"logo": SKULL_LOGO}

@router.get("/api/dashboard")
def api_dashboard():
    """Return aggregated dashboard stats."""
    modules = _module_service.discover()
    exploit_count = 0
    aux_count = 0
    cve_exploits = []
    categories = {}
    for path, cls in modules.items():
        try:
            inst = cls()
            if isinstance(inst, BaseExploitModule):
                exploit_count += 1
                if inst.cve:
                    cve_exploits.append({
                        "cve": inst.cve,
                        "name": inst.name,
                        "cvss": inst.cvss,
                        "date": inst.disclosure_date,
                    })
            else:
                aux_count += 1
            # categorize by path
            parts = path.split("/")
            cat = parts[0] if parts else "other"
            if cat not in categories:
                categories[cat] = 0
            categories[cat] += 1
        except Exception:
            continue

    session_list = sessions.list()
    active_sessions = len(session_list)

    from webforg.core.session import listeners
    listener_list = listeners.list()
    active_listeners = len(listener_list)

    sploitus = get_sploitus_stats()

    top10 = get_top10()
    top10_count = len(top10)

    # Sort CVE exploits by CVSS descending
    cve_exploits.sort(key=lambda x: x.get("cvss", 0) or 0, reverse=True)

    return {
        "modules": {
            "total": len(modules),
            "exploits": exploit_count,
            "auxiliary": aux_count,
            "categories": categories,
        },
        "sessions": {
            "active": active_sessions,
            "sessions": [
                {
                    "id": s.id,
                    "target": f"{s.target.host}:{s.target.port}" if s.target else None,
                    "module_name": s.module_name,
                    "session_type": s.session_type,
                    "created_at": s.created_at,
                }
                for s in session_list
            ],
        },
        "listeners": {
            "active": active_listeners,
        },
        "cve_exploits": {
            "total": sploitus.get("total_exploits", 0),
            "unique_cves": sploitus.get("unique_cves", 0),
            "by_type": sploitus.get("by_type", {}),
            "last_fetch": sploitus.get("last_fetch"),
            "top": cve_exploits[:20],
        },
        "owasp_top10": {
            "total": top10_count,
        },
    }
