"""Dork / phishing / port-scan routes for the WebForge HTTP API."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request

from webforg.core.dork import get_dork_library, run_dorks
from webforg.core.phish import (
    list_templates,
    render_template,
    set_manual_url,
    tunnel_start,
    tunnel_status,
    tunnel_stop,
)
from webforg.engine.scanner import (
    COMMON_PORTS,
    parse_ports as parse_port_spec,
    scan as port_scan,
)
from webforg.apps.api.models import (
    DorkRunReq,
    PortScanReq,
    TemplateRenderReq,
    TunnelManualReq,
    TunnelStartReq,
    TunnelStopReq,
)
from webforg.apps.api.shared import _audit, _client_ip

router = APIRouter()


@router.post("/api/dork/run")
def api_dork_run(req: DorkRunReq):
    """Run a dork query against one or more search engines."""
    return run_dorks(query=req.query, engines=req.engines, limit=req.limit, target=req.target)

@router.get("/api/dork/library")
def api_dork_library():
    """Return the curated dork library grouped by category."""
    return {"categories": get_dork_library()}

@router.get("/api/phish/tunnel/status")
def api_phish_tunnel_status():
    """Report installed/running tunnel tools."""
    return tunnel_status()

@router.post("/api/phish/tunnel/start")
def api_phish_tunnel_start(req: TunnelStartReq):
    """Start a public tunnel to a local phishing server."""
    return tunnel_start(tool=req.tool, port=req.port, remote=req.remote, remote_port=req.remote_port)

@router.post("/api/phish/tunnel/stop")
def api_phish_tunnel_stop(req: TunnelStopReq):
    """Stop a running tunnel."""
    return tunnel_stop(req.tool)

@router.post("/api/phish/tunnel/manual")
def api_phish_tunnel_manual(req: TunnelManualReq):
    """Save a manually obtained public URL (used as the default {link} variable)."""
    return set_manual_url(req.url)

@router.get("/api/phish/templates")
def api_phish_templates():
    """Return the SMS and email template libraries."""
    return list_templates()

@router.post("/api/phish/template/render")
def api_phish_template_render(req: TemplateRenderReq):
    """Render a template with variable substitution."""
    return render_template(kind=req.kind, template_id=req.template_id, variables=req.variables)

@router.get("/api/portscan/ports")
def api_portscan_common_ports():
    """Return the list of commonly-scanned ports."""
    return {"ports": COMMON_PORTS}

@router.post("/api/portscan/scan")
def api_portscan(req: PortScanReq, request: Request):
    """Run a threaded TCP connect scan with banner grabbing."""
    if req.ports in ("common", "", "default"):
        ports = list(COMMON_PORTS)
    elif req.ports in ("all", "*"):
        ports = list(range(1, 65536))
    else:
        ports = parse_port_spec(req.ports)
    if not ports:
        raise HTTPException(status_code=400, detail="No valid ports in spec")
    if not req.host.strip():
        raise HTTPException(status_code=400, detail="No target host supplied")
    _audit("portscan", ip=_client_ip(request), host=req.host, ports=len(ports))
    return port_scan(host=req.host, ports=ports, timeout=req.timeout,
                     workers=req.workers, grab_banners=req.grab_banners, use_ssl=req.use_ssl)
