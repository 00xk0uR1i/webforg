"""Data breach / infostealer exposure checker (multi-source).

Checks whether an email or username appears in leaked databases and
infostealer malware logs:

- Hudson Rock: infostealer logs (free, no key required) — email + username.
- HaveIBeenPwned: known database breaches (requires a HIBP v3 API key via the
  HIBP_API_KEY environment variable) — email only.
- emailrep.io: email reputation + breach aggregation (requires an API key via
  the EMAILREP_API_KEY environment variable) — email only.
"""

from __future__ import annotations

import os
from typing import Optional

import httpx

UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
)

HUDSON_HOST = "https://cavalier.hudsonrock.com/api/json/v2/osint-tools"


def _env(name: str) -> str:
    return os.environ.get(name, "").strip()


def _summarize_stealer(st: dict) -> dict:
    return {
        "stealer_family": st.get("stealer_family"),
        "os": st.get("operating_system"),
        "date_compromised": st.get("date_compromised"),
        "computer_name": st.get("computer_name"),
        "malware_path": st.get("malware_path"),
        "ip": st.get("ip"),
        "antiviruses": st.get("antiviruses") or [],
        "top_logins": st.get("top_logins") or [],
        "top_passwords": st.get("top_passwords") or [],
        "corporate_services": st.get("total_corporate_services", 0),
        "user_services": st.get("total_user_services", 0),
    }


def _check_hudson(client: httpx.Client, target: str, mode: str) -> dict:
    url = f"{HUDSON_HOST}/search-by-{mode}?{mode}={target}"
    src = {
        "id": "hudson_rock",
        "name": "Hudson Rock",
        "enabled": True,
        "exposed": False,
        "stealers": [],
        "total_infections": 0,
        "total_corporate_services": 0,
        "total_user_services": 0,
        "error": None,
    }
    try:
        r = client.get(url, headers={"User-Agent": UA, "Accept": "application/json"}, timeout=20)
        r.raise_for_status()
        data = r.json()
    except httpx.HTTPStatusError as e:
        src["error"] = f"Hudson Rock HTTP {e.response.status_code}"
        return src
    except httpx.HTTPError as e:
        src["error"] = f"Hudson Rock: {e}"
        return src
    stealers = [_summarize_stealer(s) for s in (data.get("stealers") or [])]
    src["exposed"] = bool(stealers)
    src["stealers"] = stealers
    src["total_infections"] = len(stealers)
    src["total_corporate_services"] = data.get("total_corporate_services") or 0
    src["total_user_services"] = data.get("total_user_services") or 0
    return src


def _check_hibp(client: httpx.Client, target: str) -> dict:
    src = {
        "id": "hibp",
        "name": "HaveIBeenPwned",
        "enabled": bool(_env("HIBP_API_KEY")),
        "exposed": False,
        "breaches": [],
        "error": None,
    }
    if not src["enabled"]:
        src["error"] = "Not configured — set HIBP_API_KEY to enable HaveIBeenPwned lookups"
        return src
    try:
        r = client.get(
            f"https://haveibeenpwned.com/api/v3/breachedaccount/{target}?truncateResponse=false&includeUnverified=true",
            headers={"User-Agent": UA, "hibp-api-key": _env("HIBP_API_KEY"), "Accept": "application/json"},
            timeout=25,
        )
    except httpx.HTTPError as e:
        src["error"] = f"HaveIBeenPwned: {e}"
        return src
    if r.status_code == 404:
        return src
    if r.status_code == 401:
        src["error"] = "HaveIBeenPwned rejected the API key (check HIBP_API_KEY)"
        return src
    if r.status_code != 200:
        src["error"] = f"HaveIBeenPwned HTTP {r.status_code}"
        return src
    try:
        data = r.json()
    except Exception:
        src["error"] = "HaveIBeenPwned returned an unparseable response"
        return src
    src["exposed"] = bool(data)
    src["breaches"] = [
        {
            "name": b.get("Name"),
            "title": b.get("Title"),
            "domain": b.get("Domain"),
            "breach_date": b.get("BreachDate"),
            "added_date": b.get("AddedDate"),
            "pwn_count": b.get("PwnCount"),
            "data_classes": b.get("DataClasses") or [],
            "description": b.get("Description"),
            "verified": b.get("IsVerified"),
            "sensitive": b.get("IsSensitive"),
            "fabricated": b.get("IsFabricated"),
            "spam_list": b.get("IsSpamList"),
        }
        for b in data
    ]
    return src


def _check_emailrep(client: httpx.Client, target: str) -> dict:
    src = {
        "id": "emailrep",
        "name": "emailrep.io",
        "enabled": bool(_env("EMAILREP_API_KEY")),
        "exposed": False,
        "leaked": False,
        "reputation": None,
        "suspicious": None,
        "profiles": 0,
        "breaches": [],
        "error": None,
    }
    if not src["enabled"]:
        src["error"] = "Not configured — set EMAILREP_API_KEY to enable emailrep.io lookups"
        return src
    try:
        r = client.get(
            f"https://emailrep.io/{target}",
            headers={"User-Agent": UA, "KEY": _env("EMAILREP_API_KEY"), "Accept": "application/json"},
            timeout=20,
        )
    except httpx.HTTPError as e:
        src["error"] = f"emailrep.io: {e}"
        return src
    if r.status_code in (401, 403):
        src["error"] = "emailrep.io rejected the API key (check EMAILREP_API_KEY)"
        return src
    if r.status_code == 404:
        return src
    if r.status_code != 200:
        src["error"] = f"emailrep.io HTTP {r.status_code}"
        return src
    try:
        data = r.json()
    except Exception:
        src["error"] = "emailrep.io returned an unparseable response"
        return src
    details = data.get("details") or {}
    src["reputation"] = data.get("reputation")
    src["suspicious"] = data.get("suspicious")
    src["leaked"] = bool(details.get("credentials_leaked"))
    src["profiles"] = len(details.get("profiles") or [])
    src["exposed"] = bool(details.get("credentials_leaked")) or bool(details.get("data_breaches"))
    src["breaches"] = [
        {
            "name": b.get("name") if isinstance(b, dict) else b,
            "date": b.get("date") if isinstance(b, dict) else None,
        }
        for b in (details.get("data_breaches") or [])
    ]
    return src


def check(query: str, mode: str = "email") -> dict:
    """Check an email/username against leak and infostealer databases."""
    target = (query or "").strip()
    if not target:
        return {"success": False, "error": "Empty query"}
    mode = (mode or "email").lower()
    if mode not in ("email", "username"):
        return {"success": False, "error": f"Unknown mode '{mode}'"}

    sources: list[dict] = []
    with httpx.Client(http2=False, follow_redirects=True) as client:
        sources.append(_check_hudson(client, target, mode))
        if mode == "email":
            sources.append(_check_hibp(client, target))
            sources.append(_check_emailrep(client, target))

    exposed = any(s.get("exposed") for s in sources)
    enabled_sources = [s["name"] for s in sources if s["enabled"]]
    found_sources = [s["name"] for s in sources if s.get("exposed")]
    if not enabled_sources:
        message = f"No breach sources are enabled for this lookup. Set HIBP_API_KEY and/or EMAILREP_API_KEY."
    elif exposed:
        message = f"{target} found in: {', '.join(found_sources)}."
    else:
        message = f"No known exposure for {target} across {', '.join(enabled_sources)}."

    return {
        "success": True,
        "query": target,
        "mode": mode,
        "exposed": exposed,
        "message": message,
        "sources": sources,
    }


def sources() -> dict:
    return {
        "providers": [
            {
                "id": "hudson_rock",
                "name": "Hudson Rock",
                "enabled": True,
                "source": "Infostealer malware logs",
                "modes": ["email", "username"],
                "key_needed": None,
            },
            {
                "id": "hibp",
                "name": "HaveIBeenPwned",
                "enabled": bool(_env("HIBP_API_KEY")),
                "source": "Known database breaches",
                "modes": ["email"],
                "key_needed": "HIBP_API_KEY",
            },
            {
                "id": "emailrep",
                "name": "emailrep.io",
                "enabled": bool(_env("EMAILREP_API_KEY")),
                "source": "Email reputation & breach aggregation",
                "modes": ["email"],
                "key_needed": "EMAILREP_API_KEY",
            },
        ],
        "note": "Passwords and logins returned by providers are masked. Credentials shown are never plaintext.",
    }
