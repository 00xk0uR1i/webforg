"""Payload / encoder / fingerprint routes for the WebForge HTTP API."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException

from webforg.core.encoder import (
    encode as payload_encode,
    list_encoders as payload_encoders_list,
)
from webforg.core.payload import get_payload, list_payloads
from webforg.core.target import Target
from webforg.apps.api.models import FingerprintReq, GeneratePayloadReq

router = APIRouter()


@router.post("/api/fingerprint")
def api_fingerprint(req: FingerprintReq):
    target = Target(host=req.host, port=req.port, ssl=req.ssl, path=req.path)
    try:
        fp = target.fingerprint()
        return {"fingerprint": fp}
    except Exception as e:
        raise HTTPException(500, str(e))

@router.get("/api/payloads")
def api_list_payloads():
    names = list_payloads()
    result = []
    for name in names:
        cls = get_payload(name)
        if cls:
            inst = cls()
            result.append({"name": name, "description": inst.description, "language": inst.language})
    return {"payloads": result}

@router.get("/api/encoders")
def api_list_encoders():
    """Return available payload encoders."""
    return {"encoders": payload_encoders_list()}

@router.post("/api/payloads/generate")
def api_generate_payload(req: GeneratePayloadReq):
    cls = get_payload(req.name)
    if cls is None:
        raise HTTPException(404, "Payload not found")
    inst = cls(lhost=req.lhost, lport=req.lport)
    raw = inst.generate()
    shell_langs = {"bash", "sh", "python", "python3", "perl", "ruby", "node", "powershell", "nc"}
    applicable = getattr(inst, "language", "") in shell_langs
    enc = req.encoder or "none"
    if not applicable and enc not in ("none", "url"):
        return {"payload": raw, "one_liner": inst.one_liner, "encoder": "none",
                "raw": raw, "note": f"Encoder not applicable to {inst.language} payloads"}
    try:
        encoded = payload_encode(raw, enc)
        encoded_ol = payload_encode(inst.one_liner, enc)
    except ValueError as e:
        raise HTTPException(400, str(e))
    return {"payload": encoded, "one_liner": encoded_ol, "encoder": enc, "raw": raw}

@router.get("/api/shells/generate")
def api_generate_shells(lhost: str = "127.0.0.1", lport: int = 4444, lang: str = "all", encoder: str = "none"):
    """Generate reverse shell payloads."""
    from webforg.core.shellgen import ShellGenerator
    sg = ShellGenerator(lhost, lport)
    if lang == "all":
        shells = sg.generate_all()
    else:
        shells = sg.for_language(lang)
    try:
        encoded = [payload_encode(s.cmd, encoder) for s in shells]
    except ValueError as e:
        raise HTTPException(400, str(e))
    return {
        "shells": [
            {"name": s.name, "language": s.language, "os": s.os, "cmd": enc, "raw": s.cmd, "description": s.description}
            for s, enc in zip(shells, encoded)
        ],
        "encoder": encoder,
        "listener": f"nc -lvnp {lport}",
        "msf_listener": ShellGenerator.meterpreter_listener(lhost, lport),
    }
