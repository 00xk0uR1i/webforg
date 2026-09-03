"""Face Intelligence / Reverse Face Search module."""

from __future__ import annotations

from webforg.core.module import BaseAuxiliaryModule, Option
from webforg.core.services.face_search_service import FaceSearchService
from rich.console import Console

console = Console()

MODULE_META = {
    "name": "Face Intelligence Search",
    "description": "Detect faces, generate embeddings, and search authorized/local face index",
    "author": "WebForge",
    "rank": "manual",
    "type": "auxiliary",
    "category": "osint",
    "options": {
        "ACTION": {
            "value": "search",
            "description": "Action: detect, search, index_add, index_list",
        },
    },
}


class Scanner(BaseAuxiliaryModule):
    """Face Intelligence — detect, embed, and search faces against a local index."""

    name = "Face Intelligence Search"
    description = "Detect faces, generate embeddings, and search authorized/local face index"
    author = "webforg"
    rank = "manual"

    def _build_options(self) -> None:
        super()._build_options()
        self.add_option(
            "INPUT",
            Option(
                str,
                required=False,
                default=None,
                description="Path to image file (for detect/index_add)",
            ),
        )
        self.add_option(
            "ACTION",
            Option(
                str,
                required=False,
                default="search",
                description="Action: detect, search, index_add, index_list, providers, history",
            ),
        )
        self.add_option(
            "EMBEDDING",
            Option(
                str,
                required=False,
                default=None,
                description="JSON embedding array (for search)",
            ),
        )
        self.add_option(
            "MIN_SIMILARITY",
            Option(
                float,
                required=False,
                default=0.5,
                description="Minimum similarity threshold for search",
            ),
        )
        self.add_option(
            "SOURCE_URL",
            Option(
                str,
                required=False,
                default="",
                description="Source URL for indexed image",
            ),
        )
        self.add_option(
            "TITLE",
            Option(
                str,
                required=False,
                default="",
                description="Title for indexed image",
            ),
        )
        self.add_option(
            "SOURCE_TYPE",
            Option(
                str,
                required=False,
                default="local",
                description="Source type for indexed image",
            ),
        )
        self.add_option(
            "ENTRY_ID",
            Option(
                str,
                required=False,
                default=None,
                description="Index entry ID to remove",
            ),
        )

    def run(self) -> dict:
        action = (self.get_option("ACTION") or "search").strip().lower()
        svc = FaceSearchService()

        if action == "detect":
            return self._action_detect(svc)
        elif action == "search":
            return self._action_search(svc)
        elif action == "index_add":
            return self._action_index_add(svc)
        elif action == "index_list":
            return self._action_index_list(svc)
        elif action == "index_remove":
            return self._action_index_remove(svc)
        elif action == "providers":
            return self._action_providers(svc)
        elif action == "history":
            return self._action_history(svc)
        else:
            return {"success": False, "error": f"Unknown action: {action}"}

    def _read_image_bytes(self) -> tuple[bytes, str] | None:
        path = self.get_option("INPUT")
        if not path:
            return None
        import os

        if not os.path.isfile(path):
            return None
        filename = os.path.basename(path)
        with open(path, "rb") as fh:
            return fh.read(), filename

    def _action_detect(self, svc: FaceSearchService) -> dict:
        pair = self._read_image_bytes()
        if not pair:
            return {"success": False, "error": "INPUT file not found or not set."}
        data, filename = pair
        result = svc.detect_faces(data, filename)
        return {"success": "error" not in result, **result}

    def _action_search(self, svc: FaceSearchService) -> dict:
        import json as _json

        embedding_str = self.get_option("EMBEDDING")
        min_sim = self.get_option("MIN_SIMILARITY") or 0.5

        if embedding_str:
            try:
                embedding = _json.loads(embedding_str)
            except (ValueError, TypeError):
                return {"success": False, "error": "Invalid EMBEDDING JSON."}
        else:
            pair = self._read_image_bytes()
            if not pair:
                return {"success": False, "error": "Provide INPUT image or EMBEDDING JSON."}
            data, filename = pair
            emb_resp = svc.generate_embedding(data, filename)
            if "error" in emb_resp:
                return {"success": False, **emb_resp}
            embedding = emb_resp["embedding"]

        result = svc.search(embedding=embedding, min_similarity=min_sim)
        return {"success": True, **result}

    def _action_index_add(self, svc: FaceSearchService) -> dict:
        pair = self._read_image_bytes()
        if not pair:
            return {"success": False, "error": "INPUT file not found or not set."}
        data, filename = pair
        result = svc.add_to_index(
            image_bytes=data,
            filename=filename,
            source_url=self.get_option("SOURCE_URL") or "",
            title=self.get_option("TITLE") or "",
            source_type=self.get_option("SOURCE_TYPE") or "local",
        )
        return {"success": "error" not in result, **result}

    def _action_index_list(self, svc: FaceSearchService) -> dict:
        return {"success": True, **svc.list_index()}

    def _action_index_remove(self, svc: FaceSearchService) -> dict:
        entry_id = self.get_option("ENTRY_ID")
        if not entry_id:
            return {"success": False, "error": "ENTRY_ID is required for index_remove."}
        result = svc.remove_from_index(entry_id)
        return {"success": "error" not in result, **result}

    def _action_providers(self, svc: FaceSearchService) -> dict:
        return {"success": True, **svc.get_providers()}

    def _action_history(self, svc: FaceSearchService) -> dict:
        return {"success": True, **svc.get_search_history()}
