"""Shared service layer used by both the CLI and the FastAPI backend.

The CLI and API adapters call these services instead of wiring targets,
modules and scans independently, so business operations live in one place.
"""

from __future__ import annotations

from webforg.core.services.target_service import TargetService, ParsedTarget
from webforg.core.services.module_service import ModuleService
from webforg.core.services.scan_service import ScanService, ScanServiceError

__all__ = [
    "TargetService",
    "ParsedTarget",
    "ModuleService",
    "ScanService",
    "ScanServiceError",
]
