"""Shared orchestration around the existing scanners and scan modules.

The CLI ``scan`` command and the API ``/api/scan`` endpoint both drove the
``auxiliary/scanners/multi_handler`` module independently; the port scanner
was reached through the async task wrapper.  This service is the single entry
point for both, delegating to the existing implementations so result formats
are unchanged.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional, Union

from webforg.engine.scheduler.tasks import port_scan_task
from webforg.core.findings.adapters import finding_from_scanner_result
from webforg.core.findings.model import Finding
from webforg.core.services.module_service import ModuleService
from webforg.core.services.target_service import TargetService

MULTI_HANDLER_PATH = "auxiliary/scanners/multi_handler"


class ScanServiceError(Exception):
    """Raised when a scan cannot be orchestrated (e.g. missing module)."""


@dataclass
class ScanOutcome:
    """Scan result + the unified Findings projected from it.

    ``result`` keeps the exact historical scanner dict so existing callers and
    API response shapes are unchanged; ``findings`` is the additive,
    framework-agnostic projection.
    """

    result: dict
    findings: list = field(default_factory=list)


class ScanService:
    """Orchestrates existing scanners/modules and returns existing formats."""

    def __init__(
        self,
        modules: Optional[ModuleService] = None,
        targets: Optional[TargetService] = None,
        port_scan_impl=None,
    ):
        self.modules = modules or ModuleService()
        self.targets = targets or TargetService()
        self._port_scan = port_scan_impl or port_scan_task

    def scan_url(
        self,
        url: str,
        checks: str = "all",
        threads: Optional[int] = None,
        default_host: Optional[str] = None,
    ) -> dict:
        """Run the multi-handler web scan against a target URL.

        ``threads=None`` leaves the module's own default in place (CLI
        behavior); pass an explicit value to override (API behavior).
        Returns the multi_handler result dict unchanged.
        """
        target = self.targets.parse_url(url, default_host=default_host)
        mod = self.modules.instantiate(MULTI_HANDLER_PATH)
        if mod is None:
            raise ScanServiceError("Multi-handler module not found")
        self.targets.apply_to_module(mod, target)
        mod.set_option("CHECKS", checks)
        if threads is not None:
            mod.set_option("THREADS", threads)
        return self.modules.run(mod)

    def scan_url_findings(
        self,
        url: str,
        checks: str = "all",
        threads: Optional[int] = None,
        default_host: Optional[str] = None,
    ) -> ScanOutcome:
        """Run ``scan_url`` and also return Findings (additive).

        The existing ``scan_url`` dict result is preserved verbatim inside
        ``ScanOutcome.result``; callers that already consume it are unaffected.
        """
        result = self.scan_url(
            url, checks=checks, threads=threads, default_host=default_host
        )
        target = self.targets.parse_url(url, default_host=default_host)
        findings = finding_from_scanner_result(
            result,
            module_path=MULTI_HANDLER_PATH,
            endpoint=target.url,
            target=target.host,
        )
        return ScanOutcome(result=result, findings=findings)

    def port_scan(
        self,
        host: str,
        ports: Union[str, list] = "common",
        timeout: float = 1.5,
        workers: int = 64,
        grab_banners: bool = True,
        use_ssl: bool = False,
        progress: Optional[callable] = None,
    ) -> dict:
        """Run the existing threaded port scanner via the async task wrapper."""
        if isinstance(ports, (list, tuple)):
            ports = ",".join(str(p) for p in ports)
        return self._port_scan(
            host=host,
            ports=ports,
            timeout=timeout,
            workers=workers,
            grab_banners=grab_banners,
            use_ssl=use_ssl,
            progress=progress,
        )
