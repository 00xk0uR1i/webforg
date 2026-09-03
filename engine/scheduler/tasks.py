"""Wrappers that adapt long-running functions to the async job engine (progress-aware).

Real implementation migrated from ``webforg.core.async_tasks`` (Phase 6).  The
legacy path remains a compatibility facade re-exporting from here.
"""

from __future__ import annotations

import time
from typing import Optional

from webforg.engine.scanner import scan as _port_scan, COMMON_PORTS, parse_ports
from webforg.core.osint import scan as _osint_scan
from webforg.core.dork import run_dorks as _run_dorks
from webforg.core.cve_db import update_cve_database as _update_cve_db


def port_scan_task(host: str, ports: str = "common", timeout: float = 1.5,
                   workers: int = 64, grab_banners: bool = True, use_ssl: bool = False,
                   progress: Optional[callable] = None) -> dict:
    if ports in ("common", "", "default"):
        plist = list(COMMON_PORTS)
    elif ports in ("all", "*"):
        plist = list(range(1, 65536))
    else:
        plist = parse_ports(ports)
    if not plist:
        raise ValueError("No valid ports in spec")
    started = time.time()

    def cb(done: int, total: int) -> None:
        if progress and total:
            progress(int(done / total * 100), f"Scanning {done}/{total} ports")

    result = _port_scan(host=host, ports=plist, timeout=timeout, workers=workers,
                        grab_banners=grab_banners, use_ssl=use_ssl, progress=cb)
    result["duration"] = round(time.time() - started, 2)
    return result


def osint_scan_task(query: str, mode: str = "username", categories: Optional[list[str]] = None,
                    workers: int = 12, progress: Optional[callable] = None) -> dict:
    if progress:
        progress(10, f"Scanning '{query}' across platforms")
    result = _osint_scan(query=query, mode=mode, categories=categories, workers=workers)
    if progress:
        progress(100, "Scan complete")
    return result


def dork_task(query: str, engine: str = "ddg", limit: int = 20, target: str = "",
              progress: Optional[callable] = None) -> dict:
    if progress:
        progress(10, f"Searching '{query}' via {engine}")
    result = _run_dorks(query, engines=[engine] if engine and engine != "all" else None,
                        limit=limit, target=target or None)
    if progress:
        progress(100, "Dorking complete")
    return result


def cve_update_task(nvd_days: int = 90, sploitus_pages: int = 5,
                    progress: Optional[callable] = None) -> dict:
    if progress:
        progress(5, "Updating CVE database from NVD + CISA KEV + Sploitus")
    _update_cve_db(nvd_days=nvd_days, sploitus_pages=sploitus_pages)
    if progress:
        progress(100, "CVE database updated")
    return {"success": True, "message": "CVE database updated"}
