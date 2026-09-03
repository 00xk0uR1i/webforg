"""Face Intelligence / Reverse Face Search API routes."""

from __future__ import annotations

import json
import uuid
from pathlib import Path

from fastapi import APIRouter, File, Form, HTTPException, UploadFile

from webforg.core.services.face_search_service import FaceSearchService

router = APIRouter()


_service = FaceSearchService()

_MAX_UPLOAD_BYTES = 10 * 1024 * 1024
_ALLOWED_MIMES = {"image/jpeg", "image/png", "image/webp"}


async def _read_validated_upload(file: UploadFile) -> bytes:
    """Read upload bytes with MIME and size validation."""
    content_type = (file.content_type or "").lower()
    if content_type not in _ALLOWED_MIMES:
        raise HTTPException(
            400,
            f"Unsupported image type: {content_type or 'unknown'}. Allowed: JPG, PNG, WebP.",
        )
    data = await file.read()
    if len(data) > _MAX_UPLOAD_BYTES:
        raise HTTPException(400, "File too large. Maximum size is 10 MB.")
    if len(data) == 0:
        raise HTTPException(400, "Empty file uploaded.")
    return data


@router.post("/api/osint/face/detect")
async def detect_faces(file: UploadFile = File(...)):
    """Detect faces in an uploaded image."""
    data = await _read_validated_upload(file)
    result = _service.detect_faces(data, file.filename or "upload.jpg")
    status_code = 200
    if "error" in result:
        status_code = 422
    return result


@router.post("/api/osint/face/search")
async def search_faces(
    file: UploadFile = File(None),
    embedding_json: str = Form(None),
    face_id: int = Form(0),
    min_similarity: float = Form(0.5),
    source_type: str = Form(None)
):
    """Search the face index by uploaded image or raw embedding."""
    embedding = None

    if embedding_json:
        try:
            embedding = json.loads(embedding_json)
        except (json.JSONDecodeError, TypeError):
            raise HTTPException(400, "Invalid embedding_json. Must be a JSON array of floats.")
        if not isinstance(embedding, list) or len(embedding) == 0:
            raise HTTPException(400, "embedding_json must be a non-empty array.")

    if file is not None and embedding is None:
        data = await _read_validated_upload(file)
        emb_resp = _service.generate_embedding(data, file.filename or "search.jpg", face_id=face_id)
        if "error" in emb_resp:
            raise HTTPException(422, emb_resp["error"])
        embedding = emb_resp["embedding"]

    if embedding is None:
        raise HTTPException(400, "Provide either a file or embedding_json.")

    result = _service.search(
        embedding=embedding,
        min_similarity=min_similarity,
        source_type=source_type if source_type else None,
    )
    return result


@router.get("/api/osint/face/search/{search_id}")
async def get_search_result(search_id: str):
    """Retrieve a cached search result by ID."""
    for entry in reversed(_service._search_history):
        if entry.get("search_id") == search_id:
            return entry
    raise HTTPException(404, "Search result not found.")


@router.delete("/api/osint/face/search/{search_id}")
async def delete_search_result(search_id: str):
    """Remove a search result from history."""
    before = len(_service._search_history)
    _service._search_history = [
        h for h in _service._search_history if h.get("search_id") != search_id
    ]
    if len(_service._search_history) < before:
        return {"removed": True}
    raise HTTPException(404, "Search result not found.")


@router.get("/api/osint/face/providers")
async def get_providers():
    """List available face recognition providers."""
    return _service.get_providers()


@router.post("/api/osint/face/index")
async def add_to_index(
    file: UploadFile = File(...),
    source_url: str = Form(""),
    title: str = Form(""),
    source_type: str = Form("local")
):
    """Add an image to the local face index."""
    data = await _read_validated_upload(file)
    result = _service.add_to_index(
        image_bytes=data,
        filename=file.filename or "indexed.jpg",
        source_url=source_url,
        title=title,
        source_type=source_type,
    )
    if "error" in result:
        raise HTTPException(422, result["error"])
    return result


@router.get("/api/osint/face/index")
async def list_index():
    """List all entries in the local face index."""
    return _service.list_index()


@router.delete("/api/osint/face/index/{entry_id}")
async def remove_from_index(entry_id: str):
    """Remove an entry from the face index by ID."""
    result = _service.remove_from_index(entry_id)
    if "error" in result:
        raise HTTPException(404, result["error"])
    return result


@router.get("/api/osint/face/history")
async def get_history():
    """Get search history."""
    return _service.get_search_history()


@router.delete("/api/osint/face/history")
async def clear_history():
    """Clear search history."""
    return _service.clear_search_history()
