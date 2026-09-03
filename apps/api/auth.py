"""Authentication routes for the WebForge HTTP API."""

from __future__ import annotations

import os
import secrets as _secrets
import time as _time

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse

from webforg.apps.api.models import LoginReq
from webforg.apps.api.shared import (
    SESSION_TTL,
    _audit,
    _auth_enabled,
    _client_ip,
    _client_ip_xfwd,
    _get_or_generate_password,
    _is_login_blocked,
    _is_session_valid,
    _login_fails,
    _record_login_fail,
    _session_tokens,
)

router = APIRouter()


@router.post("/api/auth/login")
def auth_login(req: LoginReq, request: Request):
    """Authenticate and issue an httponly session cookie."""
    ip = _client_ip(request)
    ip_xfwd = _client_ip_xfwd(request)
    if not _auth_enabled():
        _audit("login", ip=ip, ip_xfwd=ip_xfwd, ok=True, auth_enabled=False)
        return {"success": True, "authenticated": True, "message": "Auth is disabled"}
    blocked, until = _is_login_blocked(ip)
    if blocked:
        _audit("login", ip=ip, ip_xfwd=ip_xfwd, ok=False, reason="rate_limited")
        raise HTTPException(status_code=429, detail=f"Too many failed attempts. Locked for {max(1, int(until - _time.time()))}s")
    expected = _get_or_generate_password()
    if not _secrets.compare_digest(req.password.encode(), expected.encode()):
        _record_login_fail(ip)
        _audit("login", ip=ip, ip_xfwd=ip_xfwd, ok=False, reason="bad_password")
        raise HTTPException(status_code=401, detail="Invalid password")
    _login_fails.pop(ip, None)
    token = _secrets.token_hex(32)
    _session_tokens[token] = _time.time() + SESSION_TTL
    _audit("login", ip=ip, ip_xfwd=ip_xfwd, ok=True)
    resp = JSONResponse({"success": True, "authenticated": True})
    resp.set_cookie(
        "webforg_session",
        token,
        httponly=True,
        samesite="lax",
        secure=os.environ.get("WEBFORGE_SSL", "0") == "1",
        max_age=SESSION_TTL,
        path="/",
    )
    return resp

@router.post("/api/auth/logout")
def auth_logout(request: Request):
    token = request.cookies.get("webforg_session")
    if token:
        _session_tokens.pop(token, None)
    resp = JSONResponse({"success": True, "authenticated": False})
    resp.delete_cookie("webforg_session")
    return resp

@router.get("/api/auth/status")
def auth_status(request: Request):
    if not _auth_enabled():
        return {"authenticated": True, "auth_enabled": False}
    return {"authenticated": _is_session_valid(request.cookies.get("webforg_session")), "auth_enabled": True}
