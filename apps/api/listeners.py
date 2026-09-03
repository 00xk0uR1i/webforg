"""C2 listener routes for the WebForge HTTP API."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException

from webforg.apps.api.models import ListenerReq
from webforg.apps.api.shared import _audit

router = APIRouter()


@router.get("/api/listeners")
def api_list_listeners():
    from webforg.core.session import listeners
    listener_list = listeners.list()
    result = []
    for l in listener_list:
        result.append({
            "name": l.name,
            "lhost": l.lhost,
            "lport": l.lport,
            "payload_type": l.payload_type,
            "running": l.running,
        })
    return {"listeners": result}

@router.post("/api/listeners")
def api_start_listener(body: ListenerReq):
    from webforg.core.session import listeners, sessions as sess_mgr
    def on_new_session(session):
        sess_mgr.register(session)
    listener = listeners.create(body.lhost, body.lport, body.payload_type, body.name, tls=body.tls)
    result = listener.start(on_session=on_new_session)
    _audit("listener_start", lhost=body.lhost, lport=body.lport, payload_type=body.payload_type)
    return {"message": result, "name": listener.name}

@router.get("/api/listeners/{name}/agent")
def api_listener_agent(name: str):
    from webforg.core.session import listeners
    l = listeners.get(name)
    if not l or not hasattr(l, "agent_source"):
        raise HTTPException(404, "C2 listener not found")
    return {
        "name": l.name,
        "lhost": getattr(l, "agent_host", l.lhost),
        "lport": l.lport,
        "tls": getattr(l, "tls", False),
        "agent": l.agent_source,
    }

@router.delete("/api/listeners/{name}")
def api_stop_listener(name: str):
    from webforg.core.session import listeners
    if listeners.remove(name):
        _audit("listener_stop", name=name)
        return {"ok": True}
    raise HTTPException(404, "Listener not found")
