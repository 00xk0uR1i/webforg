"""OWASP Top 10 routes for the WebForge HTTP API."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException

from webforg.core.top10 import get_top10, get_top10_by_rank, search_top10
from webforg.apps.api.models import CveSearchReq

router = APIRouter()


@router.get("/api/top10")
def api_top10():
    vulns = get_top10()
    return {
        "vulns": [
            {
                "rank": v.rank,
                "name": v.name,
                "owasp_id": v.owasp_id,
                "severity": v.severity,
                "cvss_range": v.cvss_range,
                "description": v.description,
                "how_it_works": v.how_it_works,
                "impact": v.impact,
                "techniques_count": len(v.techniques),
                "tools": v.tools,
                "real_world_cves": v.real_world_cves,
            }
            for v in vulns
        ]
    }

@router.get("/api/top10/{rank}")
def api_top10_detail(rank: int):
    vuln = get_top10_by_rank(rank)
    if vuln is None:
        raise HTTPException(404, "Top 10 entry not found")
    techniques = []
    for t in vuln.techniques:
        techniques.append({
            "name": t.name,
            "description": t.description,
            "payloads": t.payloads,
            "detection_patterns": t.detection_patterns,
            "evasion_tips": t.evasion_tips,
            "tools": t.tools,
            "references": t.references,
        })
    return {
        "rank": vuln.rank,
        "name": vuln.name,
        "owasp_id": vuln.owasp_id,
        "severity": vuln.severity,
        "cvss_range": vuln.cvss_range,
        "description": vuln.description,
        "how_it_works": vuln.how_it_works,
        "impact": vuln.impact,
        "techniques": techniques,
        "remediation": vuln.remediation,
        "references": vuln.references,
        "tools": vuln.tools,
        "real_world_cves": vuln.real_world_cves,
    }

@router.post("/api/top10/search")
def api_top10_search(req: CveSearchReq):
    results = search_top10(req.query)
    return {
        "vulns": [
            {
                "rank": v.rank,
                "name": v.name,
                "owasp_id": v.owasp_id,
                "severity": v.severity,
                "description": v.description[:200],
            }
            for v in results
        ],
        "count": len(results),
    }
