"""Shared state and helpers for the WebForge HTTP API routers.

Deliberately contains only genuinely shared API infrastructure: service
singletons, authentication/session state, the audit helper and small
compatibility wrappers. Business logic lives in the services / domain / engine
layers, not here.
"""

from __future__ import annotations

import json as _json
import os
import secrets as _secrets
import time as _time
from pathlib import Path

from fastapi import HTTPException

from webforg.core.config import get_settings as _get_settings
from webforg.core.logging import get_logger
from webforg.core.services import (
    TargetService,
    ModuleService,
    ScanService,
)
from webforg.core.services.job_service import JobService

_S = _get_settings()
_logger = get_logger("api")

# Shared service layer (same business logic the CLI uses).
_target_service = TargetService()
_module_service = ModuleService()
_scan_service = ScanService(modules=_module_service, targets=_target_service)
_job_service = JobService()


def _auth_enabled() -> bool:
    """Read the authoritative auth flag from the assembly module at call time.

    Keeps ``monkeypatch.setattr(rpc_server, "AUTH_ENABLED", ...)`` and the
    ``start_web(auth=True)`` override effective for every router without a
    circular import (this module is imported during the assembly import).
    """
    from webforg.core.rpc_server import AUTH_ENABLED
    return AUTH_ENABLED


def _get_job_service():
    """Return the assembly's job service so test patches to ``rpc_server._job_service`` apply."""
    from webforg.core.rpc_server import _job_service
    return _job_service


SESSION_TTL = _S.session_ttl

_session_tokens: dict[str, float] = {}

LOGIN_MAX_FAILS = 5

LOGIN_LOCK_SECS = 60

_login_fails: dict[str, tuple[int, float]] = {}

_AUDIT_DIR = Path(os.path.expanduser("~/.webforg"))

_AUDIT_LOG = _AUDIT_DIR / "audit.log"

_PW_FILE = _AUDIT_DIR / "admin_password.txt"

def _client_ip(request) -> str:
    """Return the direct client IP (for rate limiting).

    Uses the socket peer address first — never trusts X-Forwarded-For for
    rate limiting or audit identity, because that header is trivially
    spoofable.  X-Forwarded-For is only used for the ``_audit()`` trail
    when present.
    """
    try:
        return request.client.host if request.client else "unknown"
    except Exception:
        return "unknown"


def _client_ip_xfwd(request) -> str:
    """Return client IP *including* X-Forwarded-For (audit trail only)."""
    try:
        fwd = request.headers.get("x-forwarded-for", "")
        if fwd:
            return fwd.split(",")[0].strip()
        return request.client.host if request.client else "unknown"
    except Exception:
        return "unknown"

def _audit(action: str, **fields) -> None:
    """Append a JSONL audit entry to ~/.webforg/audit.log.

    If the log file cannot be written (permissions, disk full, etc.) the
    entry is emitted to stderr so it is never silently lost.
    """
    import sys as _sys
    try:
        _AUDIT_DIR.mkdir(parents=True, exist_ok=True)
        rec = {"ts": _time.time(), "action": action}
        rec.update({k: (str(v)[:400] if not isinstance(v, (int, float, bool)) else v) for k, v in fields.items()})
        line = _json.dumps(rec, default=str) + "\n"
        with open(_AUDIT_LOG, "a", encoding="utf-8") as f:
            f.write(line)
        # Ensure the audit log is never world-readable.
        try:
            _AUDIT_LOG.chmod(0o600)
        except Exception:
            pass
    except Exception:
        try:
            print(f"[audit-fallback] {line.rstrip()}", file=_sys.stderr)
        except Exception:
            pass


def _safe_error_detail(exc: Exception) -> str:
    """Return a generic error string safe for external responses.

    Never leaks file paths, stack traces, or internal state.
    """
    return f"Internal error: {type(exc).__name__}"

def _configured_password() -> str | None:
    pw = os.environ.get("WEBFORGE_PASSWORD") or os.environ.get("WEBFORGE_AUTH_PASSWORD")
    return pw or None

def _get_or_generate_password() -> str:
    pw = _configured_password()
    if pw:
        return pw
    try:
        if _PW_FILE.exists():
            existing = _PW_FILE.read_text(encoding="utf-8").strip()
            if existing:
                os.environ["WEBFORGE_PASSWORD"] = existing
                return existing
    except Exception:
        pass
    generated = _secrets.token_urlsafe(12)
    os.environ["WEBFORGE_PASSWORD"] = generated
    try:
        _AUDIT_DIR.mkdir(parents=True, exist_ok=True)
        _PW_FILE.write_text(generated, encoding="utf-8")
        _PW_FILE.chmod(0o600)
    except Exception:
        pass
    print("\n" + "=" * 60)
    print("[!] No WEBFORGE_PASSWORD set — generated admin password.")
    print(f"    Saved to {_PW_FILE} (readable by root only).")
    print("    Re-run with WEBFORGE_PASSWORD to set your own.")
    print("=" * 60 + "\n")
    return generated

def _is_login_blocked(ip: str) -> tuple[bool, float]:
    fails, until = _login_fails.get(ip, (0, 0.0))
    if fails >= LOGIN_MAX_FAILS and _time.time() < until:
        return True, until
    return False, 0.0

def _record_login_fail(ip: str) -> None:
    fails, until = _login_fails.get(ip, (0, 0.0))
    if until and _time.time() > until:
        fails, until = 0, 0.0
    fails += 1
    if fails >= LOGIN_MAX_FAILS:
        until = _time.time() + LOGIN_LOCK_SECS
    _login_fails[ip] = (fails, until)

def _is_session_valid(token: str | None) -> bool:
    if not token:
        return False
    exp = _session_tokens.get(token)
    if exp is None:
        return False
    if _time.time() > exp:
        _session_tokens.pop(token, None)
        return False
    return True

def _require_authenticated(request):
    if not _auth_enabled():
        return None
    if not _is_session_valid(request.cookies.get("webforg_session")):
        raise HTTPException(status_code=401, detail="Authentication required")
    return None

def _parse_url(url: str):
    """Compatibility wrapper over TargetService.parse_url (returns a tuple)."""
    t = _target_service.parse_url(url, default_host="127.0.0.1")
    return t.host, t.port, t.ssl, t.path
