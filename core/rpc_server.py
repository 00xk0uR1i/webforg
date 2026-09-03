"""FastAPI RPC server for the WebForge web UI.

Application assembly layer: builds the FastAPI ``app``, mounts the feature
routers from :mod:`webforg.apps.api`, installs the auth/audit middleware and the
global exception handler, serves the SPA frontend and exposes the server entry
points.

Import-compatible with the historical monolith:

    from webforg.core.rpc_server import app
"""

from __future__ import annotations

import os
import stat
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse

from webforg.core.bb_workspace import router as bb_router
from webforg.core.config import get_settings as _get_settings
from webforg.core.logging import configure_logging
from webforg.core.session import sessions
from webforg.core.workspace import WORKSPACE_DIR
from webforg.apps.api import (
    ai as _ai,
    auth as _auth,
    cms as _cms,
    credsdb as _credsdb,
    cve as _cve,
    face_search as _face_search,
    intel as _intel,
    jobs as _jobs,
    listeners as _listeners,
    modules as _modules,
    osint as _osint,
    payloads as _payloads,
    scanner as _scanner,
    sessions as _sessions,
    shared as _shared,
    social as _social,
    tools as _tools,
    top10 as _top10,
    workspaces as _workspaces,
)
from webforg.apps.api.shared import (
    _audit,
    _client_ip,
    _get_or_generate_password,
    _is_session_valid,
    _job_service,
    _logger,
    _module_service,
    _safe_error_detail,
    _scan_service,
)

_S = _get_settings()
AUTH_ENABLED = _S.auth_enabled

import traceback as _traceback


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Restrict default file permissions for any files we create (DB, TLS keys,
    # audit log).  Original umask is restored on shutdown so child processes
    # spawned by the user are unaffected.
    original_umask = os.umask(0o077)
    configure_logging()
    _logger.info(
        "API startup host=%r port=%r auth_enabled=%r",
        _S.host,
        _S.port,
        _S.auth_enabled,
    )
    yield
    os.umask(original_umask)
    _logger.info("API shutdown")

app = FastAPI(title="WebForge API", version="0.1.0", lifespan=lifespan)

app.include_router(bb_router)
app.include_router(_auth.router)
app.include_router(_modules.router)
app.include_router(_sessions.router)
app.include_router(_listeners.router)
app.include_router(_payloads.router)
app.include_router(_workspaces.router)
app.include_router(_cve.router)
app.include_router(_top10.router)
app.include_router(_scanner.router)
app.include_router(_cms.router)
app.include_router(_social.router)
app.include_router(_tools.router)
app.include_router(_ai.router)
app.include_router(_intel.router)
app.include_router(_osint.router)
app.include_router(_face_search.router)
app.include_router(_credsdb.router)
app.include_router(_jobs.router)

@app.exception_handler(Exception)
async def _unhandled_exception_handler(request, exc):
    try:
        _logger.error("Unhandled exception on %s %s\n%s", request.method, request.url.path,
                      _traceback.format_exc())
    except Exception:
        pass
    return JSONResponse(status_code=500, content={"detail": _safe_error_detail(exc)})

@app.middleware("http")
async def _audit_middleware(request, call_next):
    response = await call_next(request)
    if request.url.path.startswith("/api/") and request.method not in ("GET", "HEAD", "OPTIONS"):
        _audit("api", ip=_client_ip(request), method=request.method, path=request.url.path, status=response.status_code)
    return response

@app.middleware("http")
async def auth_middleware(request: Request, call_next):
    path = request.url.path
    is_api = path.startswith("/api/")
    if is_api and not path.startswith("/api/auth/"):
        if AUTH_ENABLED and not _is_session_valid(request.cookies.get("webforg_session")):
            return JSONResponse({"detail": "Authentication required"}, status_code=401)
    return await call_next(request)

STATIC_DIR = _S.webui_dist_dir

def _spa_file(full_path: str) -> Path | None:
    """Resolve a path under the static dir; fall back to index.html for SPA routes."""
    if not STATIC_DIR.is_dir():
        return None
    if not full_path or full_path.endswith("/"):
        return STATIC_DIR / "index.html"
    candidate = (STATIC_DIR / full_path).resolve()
    try:
        candidate.relative_to(STATIC_DIR.resolve())
    except ValueError:
        return None
    if candidate.is_file():
        return candidate
    return STATIC_DIR / "index.html"

@app.get("/{full_path:path}")
def spa_fallback(full_path: str):
    if full_path == "api" or full_path.startswith("api/"):
        return JSONResponse({"detail": "Not Found"}, status_code=404)
    f = _spa_file(full_path)
    if f is None:
        return JSONResponse({"detail": "Web UI not built — run `npm run build` in webui/"}, status_code=404)
    return FileResponse(f)

def _ensure_self_signed_cert(cert_dir: Path) -> tuple[str, str] | None:
    """Generate a self-signed TLS cert/key with cryptography if not present."""
    cert_file = cert_dir / "cert.pem"
    key_file = cert_dir / "key.pem"
    if cert_file.exists() and key_file.exists():
        return str(cert_file), str(key_file)
    try:
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        import datetime
    except ImportError:
        print("[!] cryptography not installed — cannot auto-generate TLS cert.")
        return None

    cert_dir.mkdir(parents=True, exist_ok=True)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "webforge.local")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=1))
        .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("webforge.local"), x509.IPAddress(_ip("127.0.0.1"))]), critical=False)
        .sign(key, hashes.SHA256())
    )
    key_file.write_bytes(
        key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption())
    )
    cert_file.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    # Restrict key file to owner-only (0o600) even if umask is wider.
    try:
        key_file.chmod(stat.S_IRUSR | stat.S_IWUSR)
        cert_file.chmod(stat.S_IRUSR | stat.S_IWUSR)
    except Exception:
        pass
    print(f"[+] Generated self-signed TLS cert: {cert_file}")
    return str(cert_file), str(key_file)

def _ip(s: str):
    from ipaddress import ip_address
    return ip_address(s)

def start_web(host: str = "0.0.0.0", port: int = 8443, auth: bool = False):
    """Start the Web UI server with optional auth and TLS."""
    global AUTH_ENABLED
    if auth:
        AUTH_ENABLED = True
        os.environ["WEBFORGE_AUTH"] = "1"
        _get_or_generate_password()

    ssl_certfile = os.environ.get("WEBFORGE_SSL_CERT")
    ssl_keyfile = os.environ.get("WEBFORGE_SSL_KEY")
    if not ssl_certfile:
        certs = _ensure_self_signed_cert(_S.certs_dir)
        if certs:
            ssl_certfile, ssl_keyfile = certs
    if ssl_certfile and ssl_keyfile:
        os.environ["WEBFORGE_SSL"] = "1"
        scheme = "https"
    else:
        scheme = "http"

    import uvicorn
    ssl_kwargs = {"ssl_certfile": ssl_certfile, "ssl_keyfile": ssl_keyfile} if ssl_certfile and ssl_keyfile else {}
    print(f"[+] WebForge Web UI: {scheme}://{host}:{port}")
    if auth:
        print(f"[+] Auth enabled — all /api endpoints require login")
    uvicorn.run(app, host=host, port=port, **ssl_kwargs)

def run_server(host: str = "127.0.0.1", port: int = 8080, auth: bool = False):
    """Compatibility alias for run_server (no TLS by default)."""
    start_web(host=host, port=port, auth=auth)



if __name__ == "__main__":
    run_server()
