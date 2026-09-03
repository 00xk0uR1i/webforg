"""CMS detection / auto-exploitation routes for the WebForge HTTP API."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException

from webforg.apps.api.models import CmsExploitReq
from webforg.apps.api.shared import _module_service, _parse_url

router = APIRouter()


@router.post("/api/cms/exploit")
def api_cms_exploit(req: CmsExploitReq):
    """Auto-detect CMS and run all exploit checks."""
    host, port, ssl_flag, path = _parse_url(req.url)
    mod = _module_service.instantiate("exploits/cms/cms_autoexploit")
    if not mod:
        raise HTTPException(500, "CMS auto-exploit module not found")
    mod.set_option("RHOSTS", host)
    mod.set_option("RPORT", port)
    mod.set_option("SSL", ssl_flag)
    mod.set_option("CMS", req.cms)
    mod.set_option("LHOST", req.lhost)
    mod.set_option("LPORT", req.lport)
    mod.set_option("SHELL_LANG", req.shell_lang)
    try:
        result = _module_service.exploit(mod)
        extra = result.extra or {}
        return {
            "success": result.success,
            "output": result.output,
            "hits": extra.get("hits", []),
        }
    except Exception as e:
        raise HTTPException(500, str(e))

@router.post("/api/cms/detect")
def api_cms_detect(req: CmsExploitReq):
    """Detect CMS type and version."""
    host, port, ssl_flag, path = _parse_url(req.url)
    mod = _module_service.instantiate("exploits/cms/cms_autoexploit")
    if not mod:
        raise HTTPException(500, "CMS auto-exploit module not found")
    mod.set_option("RHOSTS", host)
    mod.set_option("RPORT", port)
    mod.set_option("SSL", ssl_flag)
    mod.set_option("CMS", req.cms)
    try:
        result = _module_service.check(mod)
        return {
            "detected": result.vulnerable,
            "details": result.details,
            "extra": result.extra or {},
        }
    except Exception as e:
        raise HTTPException(500, str(e))
