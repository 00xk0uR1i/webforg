"""Web technology fingerprint analysis — pure analysis logic.

Migrated from ``webforg.core.target.Target.fingerprint`` (Phase 6).  The
Target class keeps ownership of HTTP fetching and delegates the *analysis* of
headers/HTML here, so the fingerprint algorithm has a single source of truth.
Pure functions — no network, no framework.
"""

from __future__ import annotations

from typing import Optional


# favicon hash DB (abbreviated — expand with real data)
KNOWN_FAVICON_HASHES = {
    "116323821": "WordPress",
    "-920601005": "Joomla",
    "1578938751": "Drupal",
    "-1831172575": "Jenkins",
    "81586312": "Tomcat",
    "-1270006812": "Confluence",
    "-2135283795": "GitHub",
}


def analyze_headers(headers: dict) -> dict:
    """Detect technologies from HTTP response headers.

    Mirrors the historical ``Target.fingerprint`` header analysis exactly.
    Returns ``{"server": ..., "technologies": [...], "js_frameworks": [...]}``.
    """
    result = {
        "server": headers.get("server"),
        "technologies": [],
        "js_frameworks": [],
    }

    set_cookie = headers.get("set-cookie", "")
    if "PHPSESSID" in set_cookie:
        result["technologies"].append("PHP")
    if "JSESSIONID" in set_cookie:
        result["technologies"].append("Java/JSP")
    if "ASP.NET_SessionId" in set_cookie or "ASPSESSIONID" in set_cookie:
        result["technologies"].append("ASP.NET")

    powered_by = headers.get("x-powered-by", "")
    if "PHP" in powered_by:
        result["technologies"].append("PHP")
    if "ASP.NET" in powered_by:
        result["technologies"].append("ASP.NET")
    if "Express" in powered_by:
        result["technologies"].append("Express")
        result["js_frameworks"].append("Express")

    return result


def analyze_html(text: str) -> dict:
    """Detect CMS / JS frameworks from page body text.

    Mirrors the historical ``Target.fingerprint`` body analysis exactly.
    Returns ``{"cms": ..., "js_frameworks": [...]}``.
    """
    result = {
        "cms": None,
        "js_frameworks": [],
    }
    low = text.lower()
    if "wp-content" in low or "/wp-json/" in low:
        result["cms"] = "WordPress"
    if "generator" in low and "joomla" in low:
        result["cms"] = "Joomla"
    if "drupal" in low and "drupal.js" in low:
        result["cms"] = "Drupal"
    if "__next_data__" in low:
        result["js_frameworks"].append("Next.js")
    if "__nuxt__" in low:
        result["js_frameworks"].append("Nuxt.js")
    if "reactroot" in low or "react" in low:
        result["js_frameworks"].append("React")
    return result


def favicon_hash(content: bytes) -> Optional[str]:
    """Compute the mmh3 favicon hash (``None`` when mmh3 is unavailable)."""
    try:
        import mmh3

        return str(mmh3.hash(content))
    except ImportError:
        return None
    except Exception:
        return None


def lookup_favicon_hash(hash_value: Optional[str]) -> Optional[str]:
    """Map a favicon hash to a known technology (``None`` when unknown)."""
    if not hash_value:
        return None
    return KNOWN_FAVICON_HASHES.get(str(hash_value))


__all__ = [
    "KNOWN_FAVICON_HASHES",
    "analyze_headers",
    "analyze_html",
    "favicon_hash",
    "lookup_favicon_hash",
]
