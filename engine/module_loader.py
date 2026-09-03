"""Module loader facade for the WebForge engine.

Re-exports the discovery / loading primitives from ``webforg.core.module``
under a clean engine-level API so that callers import from a single place.
"""

from __future__ import annotations

from typing import Optional

from webforg.core.module import (
    BaseModule,
    discover_modules,
    get_module_class,
    instantiate_module,
)

__all__ = ["list_modules", "load_module"]


def list_modules() -> dict[str, type[BaseModule]]:
    """Discover and return all loadable modules as ``{path: class}``."""
    return discover_modules()


def load_module(module_path: str) -> Optional[type[BaseModule]]:
    """Return the class for *module_path*, or ``None`` if not found."""
    return get_module_class(module_path)
