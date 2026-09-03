"""OSINT / breach / photo-upload routes for the WebForge HTTP API."""

from __future__ import annotations

import secrets
import shutil
from pathlib import Path

from fastapi import APIRouter, File, HTTPException, UploadFile

from webforg.core.breach import check as breach_check, sources as breach_sources
from webforg.core.osint import platforms as osint_platforms, scan as osint_scan
from webforg.apps.api.models import BreachCheckReq, OsintScanReq
from webforg.apps.api.shared import _S

router = APIRouter()


OSINT_UPLOAD_DIR = _S.osint_upload_dir
OSINT_FACE_DIR = OSINT_UPLOAD_DIR / "face_set"
OSINT_UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
OSINT_FACE_DIR.mkdir(parents=True, exist_ok=True)

_IMAGE_EXTS = {".jpg", ".jpeg", ".png", ".webp", ".bmp", ".gif"}


def _save_upload(file: UploadFile, dest_dir: Path) -> Path:
    ext = Path(file.filename or "").suffix.lower()
    if ext not in _IMAGE_EXTS:
        raise HTTPException(400, f"Unsupported image type: {ext or 'unknown'}")
    name = f"{secrets.token_hex(6)}{ext}"
    dest = dest_dir / name
    with dest.open("wb") as fh:
        shutil.copyfileobj(file.file, fh)
    return dest

@router.post("/api/osint/upload")
async def api_osint_upload(file: UploadFile = File(...), kind: str = "target"):
    """Upload a photo. kind=target → input photo; kind=reference → face-match set photo."""
    try:
        if kind == "reference":
            dest = _save_upload(file, OSINT_FACE_DIR)
            return {"ok": True, "path": str(dest), "dir": str(OSINT_FACE_DIR), "filename": dest.name}
        dest = _save_upload(file, OSINT_UPLOAD_DIR)
        return {"ok": True, "path": str(dest), "dir": str(OSINT_UPLOAD_DIR), "filename": dest.name}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(500, f"Upload failed: {type(e).__name__}")

@router.get("/api/osint/facefiles")
def api_osint_facefiles():
    """List the uploaded face-match reference photos."""
    files = []
    for p in sorted(OSINT_FACE_DIR.iterdir()):
        if p.is_file() and p.suffix.lower() in _IMAGE_EXTS:
            files.append({"filename": p.name, "size": p.stat().st_size, "path": str(p)})
    return {"dir": str(OSINT_FACE_DIR), "files": files}

@router.get("/api/osint/platforms")
def api_osint_platforms():
    """Return the platform registry grouped by scan mode."""
    return osint_platforms()

@router.post("/api/osint/scan")
def api_osint_scan(req: OsintScanReq):
    """Check a username/email across many platforms (user-scanner style OSINT)."""
    return osint_scan(query=req.query, mode=req.mode, categories=req.categories, workers=req.workers)

@router.post("/api/osint/breach")
def api_osint_breach(req: BreachCheckReq):
    """Check an email/username against infostealer breach logs (Hudson Rock)."""
    return breach_check(query=req.query, mode=req.mode)

@router.get("/api/osint/breach/sources")
def api_osint_breach_sources():
    """Describe the breach data provider."""
    return breach_sources()
