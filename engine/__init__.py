"""WebForge engine — framework-agnostic execution/assessment engines.

Phase 6 separates reusable execution logic from the legacy ``webforg.core``
implementation into this package.  Engines must NOT import FastAPI, Starlette,
Uvicorn, the React/Web UI, or CLI formatting libraries.  They may depend on
``webforg.core``/domain models and on one another.

Subpackages:
  * scanner/      — TCP port scanning (pure socket logic)
  * crawler/      — HTML form / link crawling (pure parsing logic)
  * fingerprint/  — web technology fingerprint analysis (pure analysis logic)
  * scheduler/    — background job engine + task adapters (threading-based)

Legacy ``webforg.core`` paths remain valid as compatibility facades that
re-export from these engines.
"""

from __future__ import annotations
