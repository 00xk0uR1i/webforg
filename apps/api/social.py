"""Social media account-testing routes for the WebForge HTTP API."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException

from webforg.apps.api.models import SocialEnumReq, SocialLoginReq, SocialReuseReq
from webforg.apps.api.shared import _module_service

router = APIRouter()


@router.post("/api/social/login")
def api_social_login(req: SocialLoginReq):
    """Test credentials on a single social platform."""
    mod = _module_service.instantiate(f"auth/platforms/{req.platform.lower()}")
    if not mod:
        raise HTTPException(404, f"Platform '{req.platform}' not found")
    mod.set_option("RHOSTS", f"{req.platform}.com")
    mod.set_option("USERNAME", req.email)
    mod.set_option("PASSWORD", req.password)
    result = mod.attempt_login(req.email, req.password)
    return {
        "success": result.success,
        "username": result.username,
        "error_type": result.error_type,
        "response_time_ms": round(result.response_time_ms),
        "requires_2fa": result.requires_2fa,
        "status_code": result.status_code,
    }

@router.post("/api/social/enum")
def api_social_enum(req: SocialEnumReq):
    """Enumerate which platforms a user/email exists on."""
    mod = _module_service.instantiate("auth/user_enumerator")
    if not mod:
        raise HTTPException(500, "User enumerator module not found")
    if req.mode == "email":
        mod.set_option("EMAIL", req.target)
    else:
        mod.set_option("USERNAME", req.target)
    mod.set_option("MODE", req.mode)
    mod.set_option("PLATFORMS", req.platforms)
    result = _module_service.run(mod)
    raw_results = result.get("results", {})
    vulns = []
    platforms_tested = 0
    for _target, platforms in raw_results.items():
        for pname, info in platforms.items():
            platforms_tested += 1
            if info.get("exists") is True:
                vulns.append({"platform": pname, "issue": f"Account found on {pname}", "severity": "medium", "details": f"{req.target} is registered"})
            elif info.get("exists") == "error":
                vulns.append({"platform": pname, "issue": "Check error", "severity": "low", "details": info.get("error", "unknown")})
    return {"success": result.get("success", False), "platforms_tested": platforms_tested, "vulns": vulns, "raw": raw_results}

@router.post("/api/social/reuse")
def api_social_reuse(req: SocialReuseReq):
    """Test same creds across all platforms."""
    mod = _module_service.instantiate("auth/multi_platform_runner")
    if not mod:
        raise HTTPException(500, "Multi-platform runner not found")
    mod.set_option("EMAIL", req.email)
    mod.set_option("PASSWORD", req.password)
    mod.set_option("PLATFORMS", req.platforms)
    mod.set_option("DELAY_MS", req.delay)
    result = _module_service.run(mod)
    return result
