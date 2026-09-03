"""Module operations shared by the CLI and the FastAPI backend.

Discovery, metadata, instantiation, option handling and check/exploit/run are
exposed here so the CLI and API stop wiring the BaseModule system
independently.  ``webforg.core.module`` remains the source of truth for the
module contract; nothing about the module classes is changed.
"""

from __future__ import annotations

from typing import Any, Optional, Union
from pathlib import Path

from webforg.core.module import (
    BaseModule,
    BaseExploitModule,
    BaseAuxiliaryModule,
    discover_modules,
    get_module_class,
    instantiate_module,
    CheckResult,
    ExploitResult,
)


class ModuleService:
    """Reusable operations over the module system (discovery/options/exec)."""

    def __init__(self, cache: bool = True):
        # Optional per-instance instance cache so options set on a module
        # persist across calls (mirrors the historical API-side behavior).
        self._cache_enabled = cache
        self._instance_cache: dict[str, BaseModule] = {}

    # ── discovery ──

    def discover(self, base_path: Optional[Path] = None) -> dict[str, type[BaseModule]]:
        """All discovered modules as {module_path: class}."""
        return discover_modules(base_path=base_path)

    def search(self, query: str, base_path: Optional[Path] = None) -> list[tuple[str, type[BaseModule]]]:
        """Sorted (module_path, class) pairs matching query in path or class name."""
        q = (query or "").lower()
        modules = self.discover(base_path=base_path)
        return sorted(
            (path, cls) for path, cls in modules.items()
            if q in path.lower() or q in cls.__name__.lower()
        )

    # ── instantiation ──

    def get(self, module_path: str) -> Optional[type[BaseModule]]:
        """The module class for a path (lazy-loaded), or None."""
        return get_module_class(module_path)

    def instantiate(self, module_path: str, base_path: Optional[Path] = None) -> Optional[BaseModule]:
        """Create a module instance by path, or None if unknown."""
        if base_path is not None:
            cls = self.discover(base_path=base_path).get(module_path)
            if cls is None:
                return None
            inst = cls()
            inst.module_path = module_path
            return inst
        return instantiate_module(module_path)

    def get_or_create(self, module_path: str) -> Optional[BaseModule]:
        """Return a cached instance (options persist) or create a new one."""
        if module_path in self._instance_cache:
            return self._instance_cache[module_path]
        inst = instantiate_module(module_path)
        if inst is not None and self._cache_enabled:
            self._instance_cache[module_path] = inst
        return inst

    # ── metadata ──

    @staticmethod
    def metadata(module_path: str, inst: BaseModule) -> dict:
        """Standard module metadata dict (same shape the API exposes).

        Delegates to the BaseModule.metadata() contract so CLI, API and any
        new caller share a single source of truth.  Output is identical to the
        historical shape.
        """
        return inst.metadata(module_path)

    @staticmethod
    def option_descriptors(inst: BaseModule) -> dict:
        """Serializable option list for a module instance."""
        options = {}
        for name, opt in inst.options.items():
            options[name] = {
                "value": opt.get(),
                "type": opt.type.__name__,
                "required": opt.required,
                "description": opt.description,
            }
        return options

    def list_metadata(self) -> list[dict]:
        """Metadata for every discovered module (used by /api/modules)."""
        result = []
        for path, cls in sorted(self.discover().items()):
            try:
                result.append(self.metadata(path, cls()))
            except Exception:
                result.append({"path": path, "name": cls.__name__, "type": "unknown"})
        return result

    # ── option handling ──

    @staticmethod
    def set_option(inst: BaseModule, name: str, value: Any) -> None:
        inst.set_option(name, value)

    @staticmethod
    def get_option(inst: BaseModule, name: str) -> Any:
        return inst.get_option(name)

    @staticmethod
    def validate(inst: BaseModule) -> list[str]:
        """Return list of validation errors (empty when ready to run)."""
        return inst.validate()

    # ── execution ──

    @staticmethod
    def run(inst: BaseModule) -> dict:
        """Run an auxiliary module and return its results dict."""
        try:
            return inst.run()
        finally:
            ModuleService._cleanup(inst)

    @staticmethod
    def check(inst: BaseModule) -> CheckResult:
        """Run an exploit module's check() and return a CheckResult."""
        try:
            return inst.check()
        finally:
            ModuleService._cleanup(inst)

    @staticmethod
    def exploit(inst: BaseModule) -> ExploitResult:
        """Run an exploit module's exploit() and return an ExploitResult."""
        try:
            return inst.exploit()
        finally:
            ModuleService._cleanup(inst)

    @staticmethod
    def _cleanup(inst: BaseModule) -> None:
        """Invoke the lifecycle cleanup hook if the object exposes one.

        Duck-typed / fake modules (e.g. test doubles) may predate the
        ``BaseModule.cleanup()`` hook, so this is a defensive getattr that is a
        no-op for any object without a callable ``cleanup``.
        """
        cleanup = getattr(inst, "cleanup", None)
        if callable(cleanup):
            cleanup()
