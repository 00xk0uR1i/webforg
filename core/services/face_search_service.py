import cv2
import numpy as np
import tempfile
import os
import uuid
import json
import time
from pathlib import Path
from typing import Optional
from dataclasses import dataclass, field, asdict


@dataclass
class FaceBoundingBox:
    x: int
    y: int
    w: int
    h: int
    confidence: float


@dataclass
class DetectedFace:
    face_id: int
    bounding_box: FaceBoundingBox
    confidence: float


@dataclass
class FaceIndexEntry:
    id: str
    source_url: str
    title: str
    source_type: str
    embedding: list
    metadata: dict = field(default_factory=dict)
    created_at: float = field(default_factory=time.time)


@dataclass
class SearchResult:
    match_id: str
    similarity: float
    confidence_category: str
    source_url: str
    title: str
    source_type: str
    metadata: dict = field(default_factory=dict)


class FaceSearchService:
    def __init__(self):
        self._detector = None
        self._recognizer = None
        self._model_dir = Path(__file__).parent.parent.parent / "data" / "opencv"
        self._index: list[FaceIndexEntry] = []
        self._search_history: list[dict] = []
        self._init_models()

    def _init_models(self):
        detector_path = self._model_dir / "face_detection_yunet.onnx"
        recognizer_path = self._model_dir / "face_recognition_sface.onnx"
        if detector_path.exists():
            self._detector = cv2.FaceDetectorYN.create(
                str(detector_path), "", (320, 320), 0.6, 0.3
            )
        if recognizer_path.exists():
            self._recognizer = cv2.FaceRecognizerSF.create(
                str(recognizer_path), ""
            )

    def detect_faces(self, image_bytes: bytes, filename: str) -> dict:
        """Detect faces in uploaded image. Returns dict with faces list."""
        img = self._load_image(image_bytes, filename)
        if img is None:
            return {"error": "Invalid image format. Supported: JPG, PNG, WebP."}

        h, w = img.shape[:2]
        if h < 40 or w < 40:
            return {"error": "Image too small. Minimum 40x40 pixels."}
        if h * w > 4000 * 4000:
            return {"error": "Image too large. Maximum 4000x4000 pixels."}

        if self._detector is None:
            return {"error": "Face detection model not available."}

        self._detector.setInputSize((w, h))
        ok, faces = self._detector.detect(img)

        if not ok or faces is None or len(faces) == 0:
            return {"faces": [], "message": "No face detected. Try a clearer image."}

        detected = []
        for i, face in enumerate(faces):
            x, y, w_f, h_f = int(face[0]), int(face[1]), int(face[2]), int(face[3])
            conf = float(face[4])
            detected.append(
                {
                    "face_id": i,
                    "bounding_box": {
                        "x": x,
                        "y": y,
                        "w": w_f,
                        "h": h_f,
                        "confidence": conf,
                    },
                    "confidence": conf,
                }
            )

        return {"faces": detected, "image_width": w, "image_height": h}

    def generate_embedding(
        self, image_bytes: bytes, filename: str, face_id: int = 0
    ) -> dict:
        """Generate face embedding for a specific face."""
        img = self._load_image(image_bytes, filename)
        if img is None:
            return {"error": "Invalid image."}

        if self._detector is None or self._recognizer is None:
            return {"error": "Face recognition models not available."}

        h, w = img.shape[:2]
        self._detector.setInputSize((w, h))
        ok, faces = self._detector.detect(img)

        if not ok or faces is None or face_id >= len(faces):
            return {"error": f"Face {face_id} not found."}

        face = faces[face_id]
        x, y, fw, fh = (
            int(face[0]),
            int(face[1]),
            int(face[2]),
            int(face[3]),
        )
        face_img = img[max(0, y) : min(h, y + fh), max(0, x) : min(w, x + fw)]

        if face_img.size == 0:
            return {"error": "Could not extract face region."}

        embedding = self._recognizer.feature(face_img)
        if embedding is None:
            return {"error": "Could not generate embedding."}

        return {"embedding": embedding.tolist()[0], "face_id": face_id}

    def search(
        self,
        embedding: list,
        min_similarity: float = 0.5,
        source_type: Optional[str] = None,
    ) -> dict:
        """Search the local index by embedding similarity."""
        if not self._index:
            return {
                "results": [],
                "total": 0,
                "message": "No entries in face index. Add images to the index first.",
            }

        query = np.array(embedding, dtype=np.float32)
        results = []

        for entry in self._index:
            if source_type and entry.source_type != source_type:
                continue
            candidate = np.array(entry.embedding, dtype=np.float32)
            similarity = float(self._cosine_similarity(query, candidate))

            if similarity >= min_similarity:
                cat = self._categorize_confidence(similarity)
                results.append(
                    {
                        "match_id": entry.id,
                        "similarity": round(similarity, 4),
                        "confidence_category": cat,
                        "source_url": entry.source_url,
                        "title": entry.title,
                        "source_type": entry.source_type,
                        "metadata": entry.metadata,
                        "created_at": entry.created_at,
                    }
                )

        results.sort(key=lambda x: x["similarity"], reverse=True)

        search_id = str(uuid.uuid4())[:8]
        self._search_history.append(
            {
                "search_id": search_id,
                "total": len(results),
                "timestamp": time.time(),
            }
        )

        return {"results": results, "total": len(results), "search_id": search_id}

    def add_to_index(
        self,
        image_bytes: bytes,
        filename: str,
        source_url: str = "",
        title: str = "",
        source_type: str = "local",
    ) -> dict:
        """Add an image to the local face index."""
        embedding_resp = self.generate_embedding(image_bytes, filename, face_id=0)
        if "error" in embedding_resp:
            return embedding_resp

        entry_id = str(uuid.uuid4())[:8]
        entry = FaceIndexEntry(
            id=entry_id,
            source_url=source_url,
            title=title or filename,
            source_type=source_type,
            embedding=embedding_resp["embedding"],
            metadata={"filename": filename, "added_at": time.time()},
        )
        self._index.append(entry)
        return {
            "id": entry_id,
            "title": entry.title,
            "source_type": entry.source_type,
        }

    def remove_from_index(self, entry_id: str) -> dict:
        before = len(self._index)
        self._index = [e for e in self._index if e.id != entry_id]
        if len(self._index) < before:
            return {"removed": True}
        return {"error": "Entry not found"}

    def list_index(self) -> dict:
        entries = []
        for e in self._index:
            entries.append(
                {
                    "id": e.id,
                    "title": e.title,
                    "source_url": e.source_url,
                    "source_type": e.source_type,
                    "created_at": e.created_at,
                }
            )
        return {"entries": entries, "total": len(entries)}

    def get_providers(self) -> dict:
        return {
            "providers": [
                {
                    "id": "local",
                    "name": "Local (OpenCV YuNet + SFace)",
                    "enabled": self._detector is not None,
                },
                {
                    "id": "external",
                    "name": "External Provider",
                    "enabled": False,
                    "note": "Requires API key configuration",
                },
            ],
            "active": "local",
        }

    def get_search_history(self) -> dict:
        return {"history": self._search_history[-50:]}

    def clear_search_history(self) -> dict:
        self._search_history.clear()
        return {"cleared": True}

    def _load_image(self, image_bytes: bytes, filename: str) -> Optional[np.ndarray]:
        """Load image from bytes, validating format."""
        arr = np.frombuffer(image_bytes, dtype=np.uint8)
        img = cv2.imdecode(arr, cv2.IMREAD_COLOR)
        return img

    @staticmethod
    def _cosine_similarity(a: np.ndarray, b: np.ndarray) -> float:
        norm_a = np.linalg.norm(a)
        norm_b = np.linalg.norm(b)
        if norm_a == 0 or norm_b == 0:
            return 0.0
        return float(np.dot(a, b) / (norm_a * norm_b))

    @staticmethod
    def _categorize_confidence(similarity: float) -> str:
        if similarity >= 0.90:
            return "very_strong"
        elif similarity >= 0.83:
            return "strong"
        elif similarity >= 0.70:
            return "possible"
        elif similarity >= 0.50:
            return "weak"
        return "below_threshold"
