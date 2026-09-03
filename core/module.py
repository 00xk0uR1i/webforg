"""
Base module system. ALL exploits, auxiliaries, scanners inherit from these classes.
Module discovery is automatic via filesystem scanning (no registration needed).
"""

from __future__ import annotations
import contextlib
import importlib.util
import inspect
import io
import os
import re
import sys
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from webforg.core.logging import get_logger
from webforg.core.target import Target

_logger = get_logger("modules")


class _OutputTee(io.TextIOBase):
    """Text writer that mirrors everything written to sys.stdout into a buffer."""

    def __init__(self, real, rec):
        super().__init__()
        self._real = real
        self._rec = rec

    def write(self, s):
        self._real.write(s)
        self._rec.write(s)
        return len(s)

    def flush(self):
        self._real.flush()

    def writelines(self, lines):
        for line in lines:
            self.write(line)


@contextlib.contextmanager
def capture_module_output():
    """Tee all module stdout (print + rich Console) into a StringIO buffer.

    Restores sys.stdout on exit (even on exception) so module progress
    still reaches the real console while the full output is recoverable
    for the WebUI/API `output` field.
    """
    rec = io.StringIO()
    real = sys.stdout
    sys.stdout = _OutputTee(real, rec)
    try:
        yield rec
    finally:
        sys.stdout = real


def strip_ansi(text: str) -> str:
    """Remove ANSI color escape sequences so output renders cleanly."""
    return re.sub(r"\x1b\[[0-9;]*m", "", text or "")


class Option:
    """A single module option (RHOSTS, RPORT, TARGETURI, etc.)"""
    
    def __init__(
        self,
        type_: type = str,
        required: bool = False,
        default: Any = None,
        description: str = "",
        visible: bool = True,
    ):
        self.type = type_
        self.required = required
        self.default = default
        self.description = description
        self.visible = visible
        self.value = default
    
    def set(self, value: Any) -> None:
        """Set value with type coercion."""
        if self.type == bool and isinstance(value, str):
            self.value = value.lower() in ("true", "yes", "1", "on")
        elif self.type in (int, float) and isinstance(value, str):
            self.value = self.type(value)
        else:
            self.value = value
    
    def get(self) -> Any:
        return self.value
    
    def is_set(self) -> bool:
        return self.value is not None
    
    def __repr__(self) -> str:
        return f"<Option {self.value!r} (req={self.required}, type={self.type.__name__})>"


@dataclass
class CheckResult:
    """Result from a 'check' operation."""
    vulnerable: bool
    details: str = ""
    extra: dict = field(default_factory=dict)

    def to_finding(self, module=None, module_path: str = "", endpoint: str = "", target: str = "") -> list:
        """Port this CheckResult into a Finding via the Phase 5 adapters.

        Additive compatibility helper: the dataclass return value itself is
        unchanged, so existing callers keep working untouched.
        """
        from webforg.core.findings.adapters import finding_from_check_result
        return finding_from_check_result(module, self, module_path, endpoint, target)


@dataclass
class ExploitResult:
    """Result from an 'exploit' operation."""
    success: bool
    output: str = ""
    session_id: Optional[str] = None
    extra: dict = field(default_factory=dict)

    def to_finding(self, module=None, module_path: str = "", endpoint: str = "", target: str = "") -> list:
        """Port this ExploitResult into a Finding via the Phase 5 adapters.

        Additive compatibility helper: the dataclass return value itself is
        unchanged, so existing callers keep working untouched.
        """
        from webforg.core.findings.adapters import finding_from_exploit_result
        return finding_from_exploit_result(module, self, module_path, endpoint, target)


class BaseModule(ABC):
    """Base class for ALL modules (exploit, auxiliary, scanner)."""
    
    name: str = "unnamed_module"
    description: str = "No description provided."
    author: str = "unknown"
    rank: str = "normal"  # excellent > great > good > normal > manual > low
    
    def __init__(self):
        self._options: dict[str, Option] = {}
        self._build_options()
        self._target: Optional[Target] = None
    
    def _build_options(self) -> None:
        """Override in subclass to define options."""
        pass
    
    def add_option(self, name: str, option: Option) -> None:
        self._options[name] = option
    
    def set_option(self, name: str, value: Any) -> None:
        if name not in self._options:
            raise KeyError(f"Unknown option: {name}")
        self._options[name].set(value)
    
    def get_option(self, name: str) -> Any:
        if name not in self._options:
            raise KeyError(f"Unknown option: {name}")
        return self._options[name].get()
    
    @property
    def options(self) -> dict[str, Option]:
        return self._options
    
    @property
    def missing_required_options(self) -> list[str]:
        return [
            name for name, opt in self._options.items()
            if opt.required and not opt.is_set()
        ]
    
    @property
    def target(self) -> Target:
        port = self.get_option("RPORT")
        if port is None:
            port = 443 if self.get_option("SSL") else 80
        ssl_ = self.get_option("SSL") or False
        host = self.get_option("RHOSTS") or "127.0.0.1"
        if (self._target is not None
                and self._target.host == host
                and self._target.port == port
                and self._target.ssl == ssl_):
            return self._target
        self._target = Target(host=host, port=port, ssl=ssl_)
        return self._target
    
    def validate(self) -> list[str]:
        """Validate all options are properly set. Return list of errors."""
        errors = []
        for name in self.missing_required_options:
            errors.append(f"Required option '{name}' is not set")
        if "RHOSTS" in self._options and self.get_option("RHOSTS"):
            rhosts = self.get_option("RHOSTS")
            if not isinstance(rhosts, str) or not rhosts.strip():
                errors.append("RHOSTS must be a non-empty string")
        return errors

    def metadata(self, module_path: str = "") -> dict:
        """Standard, serializable metadata dict for this module instance.

        Single source of truth for the shape both the CLI and the API expose
        (``ModuleService.metadata`` delegates here).  Additive: the output is
        identical to the historical shape.
        """
        info = {
            "path": module_path,
            "name": self.name,
            "description": self.description,
            "author": self.author,
            "rank": self.rank,
        }
        if isinstance(self, BaseExploitModule):
            info["type"] = "exploit"
            info["cve"] = self.cve
            info["cvss"] = self.cvss
            info["disclosure_date"] = self.disclosure_date
        else:
            info["type"] = "auxiliary"
        return info

    def cleanup(self) -> None:
        """Lifecycle hook called after a module finishes executing.

        Default is a no-op; modules needing resource cleanup (browsers,
        sockets, temp files) override it.  Safe to add for existing modules:
        none of them override it today, so behavior is unchanged.
        """
        pass

    def __str__(self) -> str:
        return f"[{self.rank.upper()}] {self.name}"


class BaseExploitModule(BaseModule, ABC):
    """Base class for all exploit modules."""
    
    cve: Optional[str] = None
    cvss: Optional[float] = None
    disclosure_date: Optional[str] = None
    payload_compatible: list[str] = ["revshell_php"]
    
    def _build_options(self) -> None:
        self.add_option("RHOSTS",    Option(str,  required=True,  description="Target host(s)"))
        self.add_option("RPORT",     Option(int,  required=False, default=None, description="Target port"))
        self.add_option("SSL",       Option(bool, required=False, default=False, description="Use SSL"))
        self.add_option("TARGETURI", Option(str,  required=False, default="/",  description="Base path"))
        self.add_option("PAYLOAD",   Option(str,  required=False, default=None, description="Payload to use"))
    
    @abstractmethod
    def check(self) -> CheckResult:
        """Verify if target is vulnerable WITHOUT exploiting.
        Must NOT modify target state or drop a shell.
        """
        ...
    
    @abstractmethod
    def exploit(self) -> ExploitResult:
        """Execute the exploit against the target.
        May create a session.
        """
        ...


class BaseAuxiliaryModule(BaseModule, ABC):
    """Base class for auxiliary/scanner/gather modules."""
    
    def _build_options(self) -> None:
        self.add_option("RHOSTS", Option(str, required=False, description="Target host(s)"))
        self.add_option("RPORT",  Option(int, required=False, default=None, description="Target port"))
        self.add_option("SSL",    Option(bool, required=False, default=False, description="Use SSL"))
    
    @abstractmethod
    def run(self) -> dict:
        """Execute the auxiliary module. Return results dict."""
        ...


# ========== MODULE LOADER (Auto-discovery) ==========

_MODULE_CACHE: dict[str, type[BaseModule]] = {}


def discover_modules(base_path: Optional[Path] = None) -> dict[str, type[BaseModule]]:
    """Scan filesystem for all module classes. Returns {module_path: class}."""
    
    if base_path is None:
        base_path = Path(__file__).parent.parent / "modules"
    
    if not base_path.exists():
        return {}
    
    modules: dict[str, type[BaseModule]] = {}
    
    for py_file in base_path.rglob("*.py"):
        if py_file.name.startswith("__"):
            continue
        
        # Build module path: "exploit/cve/2025/CVE-2025-55182"
        rel_path = py_file.relative_to(base_path)
        module_path = str(rel_path.with_suffix("")).replace(os.sep, "/")
        
        # Load the module
        try:
            spec = importlib.util.spec_from_file_location(
                f"webforg.modules.{module_path.replace('/', '.')}",
                py_file
            )
            if spec is None or spec.loader is None:
                continue
            
            mod = importlib.util.module_from_spec(spec)
            sys.modules[f"webforg.modules.{module_path.replace('/', '.')}"] = mod
            spec.loader.exec_module(mod)
            
            # Find any BaseExploitModule or BaseAuxiliaryModule subclass
            for name, cls in inspect.getmembers(mod, inspect.isclass):
                if cls.__module__ != mod.__name__:
                    continue
                if issubclass(cls, BaseExploitModule) and cls is not BaseExploitModule:
                    modules[module_path] = cls
                elif issubclass(cls, BaseAuxiliaryModule) and cls is not BaseAuxiliaryModule:
                    modules[module_path] = cls
                    
        except Exception as e:
            _logger.debug("Failed to load module %s: %s", module_path, e)
            print(f"  [!] Failed to load {module_path}: {e}")
    
    return modules


def get_module_class(module_path: str) -> Optional[type[BaseModule]]:
    """Get a module class by path (lazy-loaded)."""
    global _MODULE_CACHE
    
    if not _MODULE_CACHE:
        _MODULE_CACHE = discover_modules()
    
    return _MODULE_CACHE.get(module_path)


def instantiate_module(module_path: str) -> Optional[BaseModule]:
    """Create an instance of a module by path."""
    cls = get_module_class(module_path)
    if cls is None:
        return None
    inst = cls()
    inst.module_path = module_path
    return inst
