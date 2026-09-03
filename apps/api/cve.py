"""CVE / Sploitus feed routes for the WebForge HTTP API."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException

from webforg.core.cve_db import (
    get_sploitus_stats,
    search_cves,
    search_sploitus_exploits,
    update_cve_database,
)
from webforg.apps.api.models import CveSearchReq

router = APIRouter()


@router.post("/api/cve/search")
def api_cve_search(req: CveSearchReq):
    results = search_cves(req.query, req.min_cvss, req.limit)
    return {"cves": results, "count": len(results)}

@router.post("/api/cve/update")
def api_cve_update(body: dict = None):
    body = body or {}
    try:
        sploitus_pages = body.get("sploitus_pages", 5)
        nvd_days = body.get("nvd_days", 90)
        update_cve_database(nvd_days=nvd_days, sploitus_pages=sploitus_pages)
        return {"ok": True}
    except Exception as e:
        raise HTTPException(500, str(e))

@router.post("/api/sploitus/search")
def api_sploitus_search(req: CveSearchReq):
    results = search_sploitus_exploits(query=req.query, limit=req.limit)
    return {"exploits": results, "count": len(results)}

@router.get("/api/sploitus/stats")
def api_sploitus_stats():
    return get_sploitus_stats()

@router.post("/api/sploitus/exploit/{exploit_id}")
def api_sploitus_exploit_detail(exploit_id: str):
    from webforg.core.cve_db import scrape_sploitus_exploit
    result = scrape_sploitus_exploit(exploit_id)
    if result is None:
        raise HTTPException(404, "Exploit not found or scrape failed")
    return result
