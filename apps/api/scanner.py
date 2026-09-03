"""Scanning / brute-force / enumeration routes for the WebForge HTTP API."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException

from webforg.core.creds import (
    add_creds as creds_add_many,
    extract_creds_from_result as creds_extract,
)
from webforg.core.services import ScanServiceError
from webforg.apps.api.models import (
    BruteForceReq,
    CredsReq,
    EnumReq,
    ScanReq,
    SprayReq,
    SploitusRunReq,
)
from webforg.apps.api.shared import _module_service, _parse_url, _scan_service

router = APIRouter()


@router.post("/api/scan")
def api_scan(req: ScanReq):
    """Auto-scan all vulnerabilities against a target URL."""
    try:
        return _scan_service.scan_url(
            req.url,
            checks=req.checks,
            threads=req.threads,
            default_host="127.0.0.1",
        )
    except ScanServiceError as e:
        raise HTTPException(500, f"Internal error: {type(e).__name__}")

@router.post("/api/bruteforce")
def api_bruteforce(req: BruteForceReq):
    """Brute force a login form."""
    host, port, ssl_flag, path = _parse_url(req.url)
    mod = _module_service.instantiate("auxiliary/scanners/brute_force")
    if not mod:
        raise HTTPException(500, "Brute force module not found")
    mod.set_option("RHOSTS", host)
    mod.set_option("RPORT", port)
    mod.set_option("SSL", ssl_flag)
    mod.set_option("TARGETURI", path)
    mod.set_option("USERNAME", req.usernames)
    if req.passwords:
        mod.set_option("PASSWORD", req.passwords)
    if req.wordlist:
        mod.set_option("WORDLIST", req.wordlist)
    if req.user_field:
        mod.set_option("USER_FIELD", req.user_field)
    if req.pass_field:
        mod.set_option("PASS_FIELD", req.pass_field)
    if req.fail_string:
        mod.set_option("FAIL_STRING", req.fail_string)
    mod.set_option("THREADS", req.threads)
    mod.set_option("DELAY", req.delay)
    result = _module_service.run(mod)
    saved = creds_add_many(creds_extract(req.url, result))
    if saved:
        result["creds_saved"] = saved
    return result

@router.post("/api/spray")
def api_spray(req: SprayReq):
    """Password spray against a login form."""
    host, port, ssl_flag, path = _parse_url(req.url)
    mod = _module_service.instantiate("auxiliary/scanners/password_spray")
    if not mod:
        raise HTTPException(500, "Password spray module not found")
    mod.set_option("RHOSTS", host)
    mod.set_option("RPORT", port)
    mod.set_option("SSL", ssl_flag)
    mod.set_option("TARGETURI", path)
    mod.set_option("USERNAMES", req.usernames)
    if req.passwords:
        mod.set_option("PASSWORDS", req.passwords)
    mod.set_option("DELAY", req.delay)
    result = _module_service.run(mod)
    saved = creds_add_many(creds_extract(req.url, result))
    if saved:
        result["creds_saved"] = saved
    return result

@router.post("/api/enum")
def api_enum(req: EnumReq):
    """Enumerate valid usernames."""
    host, port, ssl_flag, path = _parse_url(req.url)
    mod = _module_service.instantiate("auxiliary/scanners/account_enum")
    if not mod:
        raise HTTPException(500, "Account enum module not found")
    mod.set_option("RHOSTS", host)
    mod.set_option("RPORT", port)
    mod.set_option("SSL", ssl_flag)
    mod.set_option("TARGETURI", path)
    mod.set_option("USERNAMES", req.usernames)
    result = _module_service.run(mod)
    return result

@router.post("/api/creds")
def api_creds(req: CredsReq):
    """Credential stuffing with leaked user:pass pairs."""
    host, port, ssl_flag, path = _parse_url(req.url)
    mod = _module_service.instantiate("auxiliary/scanners/credential_stuffing")
    if not mod:
        raise HTTPException(500, "Credential stuffing module not found")
    mod.set_option("RHOSTS", host)
    mod.set_option("RPORT", port)
    mod.set_option("SSL", ssl_flag)
    mod.set_option("TARGETURI", path)
    mod.set_option("CREDS_FILE", req.creds_file)
    mod.set_option("THREADS", req.threads)
    mod.set_option("DELAY", req.delay)
    result = _module_service.run(mod)
    return result

@router.post("/api/sploitus/run")
def api_sploitus_run(req: SploitusRunReq):
    """Run Sploitus exploit module against a target."""
    host, port, ssl_flag, path = _parse_url(req.url)
    mod = _module_service.instantiate("exploits/sploitus_exploit")
    if not mod:
        raise HTTPException(500, "Sploitus exploit module not found")
    mod.set_option("RHOSTS", host)
    mod.set_option("RPORT", port)
    mod.set_option("SSL", ssl_flag)
    mod.set_option("TARGETURI", path)
    mod.set_option("COMMAND", req.command)
    mod.set_option("LIMIT", req.limit)
    mod.set_option("THREADS", req.threads)
    mod.set_option("TIMEOUT", req.timeout)
    if req.cve:
        mod.set_option("CVE", req.cve)
        mod.set_option("SEARCH_BY", "cve")
    elif req.cms:
        mod.set_option("CMS", req.cms)
        mod.set_option("SEARCH_BY", "cms")
    elif req.techs:
        mod.set_option("TECHS", req.techs)
        mod.set_option("SEARCH_BY", "tech")
    else:
        mod.set_option("SEARCH_BY", req.search_by)
    try:
        result = _module_service.exploit(mod)
        extra = result.extra or {}
        return {
            "success": result.success,
            "output": result.output,
            "found": extra.get("found", []),
        }
    except Exception as e:
        raise HTTPException(500, f"Internal error: {type(e).__name__}")
