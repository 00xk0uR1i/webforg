"""Session management routes for the WebForge HTTP API."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException

from webforg.core.session import sessions
from webforg.apps.api.models import CveExploitReq, SessionDownloadReq, SessionUploadReq
from webforg.apps.api.shared import _audit

router = APIRouter()


@router.get("/api/sessions")
def api_list_sessions():
    session_list = sessions.list()
    result = []
    for s in session_list:
        result.append({
            "id": s.id,
            "target": f"{s.target.host}:{s.target.port}" if s.target else None,
            "module_name": s.module_name,
            "payload_name": s.payload_name,
            "session_type": s.session_type,
            "alive": s.alive,
            "platform": s.platform,
            "hostname": s.hostname,
            "username": s.username,
            "created_at": s.created_at,
            "last_active": s.last_active,
            "workspace": s.workspace,
        })
    return {"sessions": result}

@router.post("/api/sessions/{session_id}/send")
def api_session_send(session_id: str, body: dict):
    s = sessions.get(session_id)
    if not s:
        raise HTTPException(404, "Session not found")
    command = body.get("command", "")
    _audit("session_send", session_id=session_id, command=command[:200])
    if s.session_type == "meterpreter":
        output = s.send_meterpreter(command)
    else:
        output = s.send(command)
    return {"output": output, "alive": s.alive}

@router.post("/api/sessions/{session_id}/probe")
def api_session_probe(session_id: str):
    s = sessions.get(session_id)
    if not s:
        raise HTTPException(404, "Session not found")
    stype = s.probe_shell()
    return {"session_type": stype, "platform": s.platform}

@router.post("/api/sessions/{session_id}/upgrade")
def api_session_upgrade(session_id: str):
    s = sessions.get(session_id)
    if not s:
        raise HTTPException(404, "Session not found")
    s.session_type = "meterpreter"
    return {"ok": True, "session_type": "meterpreter"}

@router.post("/api/sessions/{session_id}/download")
def api_session_download(session_id: str, req: SessionDownloadReq):
    """Download a file from the target (base64-encoded over the wire)."""
    s = sessions.get(session_id)
    if not s:
        raise HTTPException(404, "Session not found")
    _audit("session_download", session_id=session_id, path=req.remote_path)
    return s.download(req.remote_path)

@router.post("/api/sessions/{session_id}/upload")
def api_session_upload(session_id: str, req: SessionUploadReq):
    """Upload raw bytes to a path on the target."""
    s = sessions.get(session_id)
    if not s:
        raise HTTPException(404, "Session not found")
    try:
        import base64 as _b64
        data = _b64.b64decode(req.data_b64, validate=True)
    except Exception:
        raise HTTPException(400, "Invalid base64 payload")
    _audit("session_upload", session_id=session_id, path=req.remote_path, size=len(data))
    return s.upload(data, req.remote_path)

@router.post("/api/sessions/{session_id}/hashdump")
def api_session_hashdump(session_id: str):
    """Dump local account hashes (/etc/passwd, /etc/shadow)."""
    s = sessions.get(session_id)
    if not s:
        raise HTTPException(404, "Session not found")
    _audit("session_hashdump", session_id=session_id)
    return s.hashdump()

@router.post("/api/sessions/{session_id}/sysinfo")
def api_session_sysinfo(session_id: str):
    """Gather system information from the target."""
    s = sessions.get(session_id)
    if not s:
        raise HTTPException(404, "Session not found")
    _audit("session_sysinfo", session_id=session_id)
    return s.sysinfo()

@router.post("/api/sessions/{session_id}/cve-scan")
def api_session_cve_scan(session_id: str):
    """Run a container CVE scan through an active session."""
    s = sessions.get(session_id)
    if not s:
        raise HTTPException(404, "Session not found")
    from webforg.core import c2_ops
    _audit("session_cve_scan", session_id=session_id)
    return c2_ops.scan_cves(s, session_id=session_id)

@router.post("/api/sessions/{session_id}/cve-exploit")
def api_session_cve_exploit(session_id: str, req: CveExploitReq):
    """Deliver a CVE exploit PoC to an active session."""
    s = sessions.get(session_id)
    if not s:
        raise HTTPException(404, "Session not found")
    from webforg.core import c2_ops
    _audit("session_cve_exploit", session_id=session_id, cve=req.cve_id)
    return c2_ops.exploit_cve(s, req.cve_id, session_id=session_id)

@router.delete("/api/sessions/{session_id}")
def api_kill_session(session_id: str):
    if sessions.kill(session_id):
        return {"ok": True}
    raise HTTPException(404, "Session not found")
