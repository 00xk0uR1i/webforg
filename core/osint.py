"""OSINT username/email existence scanner (user-scanner style).

Checks whether a username or email is registered across many platforms by
relying on public profile pages and open APIs only. No authentication is
performed or bypassed.
"""

from __future__ import annotations

import random
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional

import httpx

UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
)


def _page(url: str, absent: tuple = (), present: tuple = (), headers: Optional[dict] = None) -> dict:
    return {"type": "page", "url": url, "absent": absent, "present": present, "headers": headers}


def _json(url: str, profile: Optional[dict] = None, headers: Optional[dict] = None) -> dict:
    return {"type": "json", "url": url, "profile": profile or {}, "headers": headers}


def _post_json(url: str, body: dict, found_msgs: tuple, not_found_msgs: tuple, headers: Optional[dict] = None, json_key: Optional[str] = None) -> dict:
    return {
        "type": "post_json",
        "url": url,
        "body": body,
        "found": found_msgs,
        "not_found": not_found_msgs,
        "headers": headers,
        "json_key": json_key,
    }


P = {
    "github": {"name": "GitHub", "category": "Development", "check": _json(
        "https://api.github.com/users/{u}",
        profile={"display_name": "name", "bio": "bio", "location": "location", "company": "company", "blog": "blog", "followers": "followers", "following": "following", "repos": "public_repos", "avatar": "avatar_url"},
    )},
    "gitlab": {"name": "GitLab", "category": "Development", "check": _json("https://gitlab.com/api/v4/users?username={u}")},
    "bitbucket": {"name": "Bitbucket", "category": "Development", "check": _json("https://api.bitbucket.org/2.0/users/{u}", profile={"display_name": "display_name", "location": "location"})},
    "hackernews": {"name": "Hacker News", "category": "Development", "check": _json("https://hacker-news.firebaseio.com/v0/user/{u}.json")},
    "replit": {"name": "Replit", "category": "Development", "check": _page("https://replit.com/@{u}", absent=("Page not found",))},
    "codepen": {"name": "CodePen", "category": "Development", "check": _page("https://codepen.io/{u}", absent=("That page could not be found", "doesn't exist"))},
    "codesandbox": {"name": "CodeSandbox", "category": "Development", "check": _page("https://codesandbox.io/u/{u}", absent=("Not Found",))},
    "npm": {"name": "npm", "category": "Development", "check": _page("https://www.npmjs.com/~{u}", absent=("Page not found",))},
    "pypi": {"name": "PyPI", "category": "Development", "check": _page("https://pypi.org/user/{u}/", absent=("Page Not Found",))},
    "dockerhub": {"name": "Docker Hub", "category": "Development", "check": _json("https://hub.docker.com/v2/users/{u}", profile={"display_name": "full_name", "location": "location"})},
    "sourceforge": {"name": "SourceForge", "category": "Development", "check": _page("https://sourceforge.net/u/{u}/", absent=("Page Not Found",))},
    "jsfiddle": {"name": "JSFiddle", "category": "Development", "check": _page("https://jsfiddle.net/user/{u}/", absent=("not found",))},
    "stackoverflow": {"name": "Stack Overflow", "category": "Development", "check": _json("https://api.stackexchange.com/2.3/users?inname={u}&site=stackoverflow&filter=!nNPvSNdWme", profile={"display_name": "display_name"})},
    "twitter": {"name": "Twitter / X", "category": "Social", "check": _page("https://twitter.com/{u}", absent=("This account doesn't exist", "This account doesn’t exist", "doesn't exist"))},
    "instagram": {"name": "Instagram", "category": "Social", "check": _page("https://www.instagram.com/{u}/", absent=("Sorry, this page isn't available", "Page Not Found"))},
    "tiktok": {"name": "TikTok", "category": "Social", "check": _page("https://www.tiktok.com/@{u}", absent=("couldn't find this account",))},
    "reddit": {"name": "Reddit", "category": "Social", "check": _json("https://www.reddit.com/user/{u}/about.json", profile={"display_name": "name", "bio": "subreddit"})},
    "linkedin": {"name": "LinkedIn", "category": "Social", "check": _page("https://www.linkedin.com/in/{u}", absent=("This profile doesn't exist", "This profile doesn’t exist", "Page not found", "Profile not found"))},
    "pinterest": {"name": "Pinterest", "category": "Social", "check": _page("https://www.pinterest.com/{u}/", absent=("doesn't exist", "Page Not Found"))},
    "telegram": {"name": "Telegram", "category": "Social", "check": _page("https://t.me/{u}", present=("tgme_page_title",))},
    "mastodon": {"name": "Mastodon.social", "category": "Social", "check": _json("https://mastodon.social/api/v1/accounts/lookup?acct={u}", profile={"display_name": "display_name", "note": "note"})},
    "threads": {"name": "Threads", "category": "Social", "check": _page("https://www.threads.net/@{u}", absent=("Sorry, this page isn't available",))},
    "snapchat": {"name": "Snapchat", "category": "Social", "check": _page("https://www.snapchat.com/add/{u}", absent=("We couldn't find", "The username doesn't exist"))},
    "vk": {"name": "VK", "category": "Social", "check": _page("https://vk.com/{u}", absent=("Page not found",))},
    "keybase": {"name": "Keybase", "category": "Social", "check": _page("https://keybase.io/{u}", absent=("Page not found", "could not be found"))},
    "gravatar": {"name": "Gravatar", "category": "Social", "check": _page("https://gravatar.com/{u}", absent=("could not be found",))},
    "xing": {"name": "Xing", "category": "Social", "check": _page("https://www.xing.com/profile/{u}", absent=("Page not found",))},
    "dev_to": {"name": "DEV Community", "category": "Social", "check": _page("https://dev.to/{u}", absent=("Page not found",))},
    "medium": {"name": "Medium", "category": "Social", "check": _page("https://medium.com/@{u}", absent=("Page not found",))},
    "hashnode": {"name": "Hashnode", "category": "Social", "check": _page("https://hashnode.com/@{u}", absent=("Page Not Found",))},
    "patreon": {"name": "Patreon", "category": "Social", "check": _page("https://www.patreon.com/{u}", absent=("Page Not Found",))},
    "buymeacoffee": {"name": "Buy Me a Coffee", "category": "Social", "check": _page("https://www.buymeacoffee.com/{u}", absent=("Page Not Found",))},
    "youtube": {"name": "YouTube", "category": "Streaming & Music", "check": _page("https://www.youtube.com/@{u}", absent=("not found",))},
    "vimeo": {"name": "Vimeo", "category": "Streaming & Music", "check": _page("https://vimeo.com/{u}", absent=("Not found", "page not found"))},
    "soundcloud": {"name": "SoundCloud", "category": "Streaming & Music", "check": _page("https://soundcloud.com/{u}", absent=("Not Found",))},
    "spotify": {"name": "Spotify", "category": "Streaming & Music", "check": _page("https://open.spotify.com/user/{u}", absent=("Page not found",))},
    "bandcamp": {"name": "Bandcamp", "category": "Streaming & Music", "check": _page("https://bandcamp.com/{u}", absent=("Page Not Found",))},
    "twitch": {"name": "Twitch", "category": "Streaming & Music", "check": _page("https://www.twitch.tv/{u}", absent=("no channel by the name", "couldn't find"))},
    "steam": {"name": "Steam", "category": "Gaming", "check": _page("https://steamcommunity.com/id/{u}", absent=("The specified profile could not be found",))},
    "minecraft": {"name": "Minecraft", "category": "Gaming", "check": _json("https://api.mojang.com/users/profiles/minecraft/{u}", profile={"display_name": "name"})},
    "roblox": {"name": "Roblox", "category": "Gaming", "check": _page("https://www.roblox.com/user.aspx?username={u}", absent=("User not found",))},
    "osu": {"name": "osu!", "category": "Gaming", "check": _page("https://osu.ppy.sh/users/{u}", absent=("not found",))},
    "disqus": {"name": "Disqus", "category": "Forums & Community", "check": _page("https://disqus.com/by/{u}/", absent=("Page Not Found",))},
    "imgur": {"name": "Imgur", "category": "Forums & Community", "check": _page("https://imgur.com/user/{u}", absent=("Page not found",))},
    "giphy": {"name": "GIPHY", "category": "Forums & Community", "check": _page("https://giphy.com/{u}", absent=("Page not found",))},
    "pastebin": {"name": "Pastebin", "category": "Forums & Community", "check": _page("https://pastebin.com/u/{u}", absent=("Page Not Found",))},
    "kaggle": {"name": "Kaggle", "category": "Development", "check": _page("https://www.kaggle.com/{u}", absent=("Page Not Found",))},
    "tryhackme": {"name": "TryHackMe", "category": "Development", "check": _page("https://tryhackme.com/p/{u}", absent=("Page Not Found",))},
    "hackthebox": {"name": "HackTheBox", "category": "Development", "check": _page("https://app.hackthebox.com/users/profile/{u}", absent=("Page not found",))},
}

EMAIL_P = {
    "instagram": {"name": "Instagram", "category": "Social", "check": _post_json(
        "https://i.instagram.com/api/v1/accounts/send_password_reset/",
        {"user_email": "{u}", "device_id": ""},
        found_msgs=(), not_found_msgs=("no users found",),
    )},
    "github": {"name": "GitHub", "category": "Development", "check": _post_json(
        "https://github.com/signup_check/email",
        {"value": "{u}"},
        found_msgs=("is already", "already used"), not_found_msgs=(),
        json_key="valid",
    )},
    "adobe": {"name": "Adobe", "category": "Creative", "check": _post_json(
        "https://auth.services.adobe.com/signup/v1/users",
        {"email": "{u}"},
        found_msgs=("email already", "already registered"), not_found_msgs=(),
    )},
    "spotify": {"name": "Spotify", "category": "Streaming & Music", "check": _post_json(
        "https://www.spotify.com/api/account-check",
        {"email": "{u}"},
        found_msgs=(), not_found_msgs=("no account", "account doesn't exist"),
    )},
    "reddit": {"name": "Reddit", "category": "Social", "check": _post_json(
        "https://www.reddit.com/api/password_reset.json",
        {"email": "{u}"},
        found_msgs=(), not_found_msgs=("invalid email", "no such user"),
    )},
}

ALL_USERNAME = list(P.keys())
ALL_EMAIL = list(EMAIL_P.keys())

USERNAME_CATEGORIES = sorted({c["category"] for c in P.values()})
EMAIL_CATEGORIES = sorted({c["category"] for c in EMAIL_P.values()})


def _dotted(obj: dict, path: str):
    cur = obj
    for part in path.split("."):
        if isinstance(cur, dict):
            cur = cur.get(part)
        else:
            return None
    return cur


def _extract_profile(data, profile_map: dict) -> dict:
    out = {}
    for out_key, path in profile_map.items():
        val = _dotted(data, path) if isinstance(data, dict) else None
        if val is not None and val != "":
            out[out_key] = val
    return out


def _check_one(target: str, pid: str, cfg: dict, client: httpx.Client) -> dict:
    entry = {"platform": pid, "name": cfg["name"], "category": cfg["category"], "status": "error", "url": "", "profile": {}}
    check = cfg["check"]
    url = check["url"].format(u=target)
    entry["url"] = url
    headers = {"User-Agent": UA, "Accept": "application/json,text/html,*/*", "Accept-Encoding": "identity"}
    headers.update(check.get("headers") or {})
    try:
        if check["type"] == "page":
            r = client.get(url, headers=headers, timeout=14, follow_redirects=True)
            text = r.text.lower()
            absent = [s.lower() for s in check["absent"]]
            present = [s.lower() for s in check["present"]]
            if r.status_code in (404, 410):
                entry["status"] = "not_found"
            elif r.status_code != 200:
                entry["status"] = "error"
                entry["detail"] = f"HTTP {r.status_code}"
            elif absent and any(a in text for a in absent):
                entry["status"] = "not_found"
            elif present and not any(p in text for p in present):
                entry["status"] = "not_found"
            else:
                entry["status"] = "found"
        elif check["type"] == "json":
            r = client.get(url, headers=headers, timeout=14, follow_redirects=True)
            if r.status_code == 200:
                try:
                    data = r.json()
                except Exception:
                    data = None
                if check.get("profile") and isinstance(data, dict):
                    entry["profile"] = _extract_profile(data, check["profile"])
                entry["status"] = "found"
            elif r.status_code in (404, 410):
                entry["status"] = "not_found"
            else:
                entry["status"] = "error"
                entry["detail"] = f"HTTP {r.status_code}"
        elif check["type"] == "post_json":
            body = {k: (v.format(u=target) if isinstance(v, str) else v) for k, v in check["body"].items()}
            r = client.post(url, json=body, headers=headers, timeout=14, follow_redirects=True)
            text = r.text.lower()
            if check.get("json_key"):
                try:
                    data = r.json()
                    val = _dotted(data, check["json_key"]) if isinstance(data, dict) else None
                except Exception:
                    val = None
                if val is False:
                    entry["status"] = "found"
                elif val is True:
                    entry["status"] = "not_found"
                else:
                    entry["detail"] = f"HTTP {r.status_code} (no {check['json_key']})"
                    entry["status"] = "error"
                return entry
            if check["not_found"] and any(s.lower() in text for s in check["not_found"]):
                entry["status"] = "not_found"
            elif check["found"] and any(s.lower() in text for s in check["found"]):
                entry["status"] = "found"
            elif r.status_code in (404, 410):
                entry["status"] = "not_found"
            else:
                entry["status"] = "error"
                entry["detail"] = f"HTTP {r.status_code}"
    except Exception as e:
        entry["status"] = "error"
        entry["detail"] = str(e)[:90]
    return entry


def scan(query: str, mode: str = "username", categories: Optional[list[str]] = None, workers: int = 12) -> dict:
    target = (query or "").strip()
    if not target:
        return {"success": False, "error": "Empty query"}
    mode = (mode or "username").lower()
    if mode == "email":
        registry = EMAIL_P
        all_cats = EMAIL_CATEGORIES
    else:
        registry = P
        all_cats = USERNAME_CATEGORIES

    selected = [c for c in (categories or []) if c in all_cats]
    if not selected:
        selected = all_cats
    selected_set = set(selected)
    items = {pid: cfg for pid, cfg in registry.items() if cfg["category"] in selected_set}

    results = []
    start = time.time()
    with httpx.Client(http2=False, follow_redirects=True) as client:
        with ThreadPoolExecutor(max_workers=max(1, min(workers, 24))) as ex:
            futs = {ex.submit(_check_one, target, pid, cfg, client): pid for pid, cfg in items.items()}
            for fut in as_completed(futs):
                try:
                    results.append(fut.result())
                except Exception as e:
                    results.append({"platform": futs[fut], "name": futs[fut], "category": "?", "status": "error", "url": "", "profile": {}, "detail": str(e)[:80]})
                time.sleep(random.uniform(0.02, 0.08))

    found = [r for r in results if r["status"] == "found"]
    not_found = [r for r in results if r["status"] == "not_found"]
    errors = [r for r in results if r["status"] == "error"]
    results.sort(key=lambda r: (r["status"] != "found", r["name"].lower()))

    return {
        "success": True,
        "query": target,
        "mode": mode,
        "total": len(results),
        "found_count": len(found),
        "not_found_count": len(not_found),
        "error_count": len(errors),
        "elapsed_ms": int((time.time() - start) * 1000),
        "categories": selected,
        "results": results,
    }


def platforms() -> dict:
    return {
        "username": {
            "categories": USERNAME_CATEGORIES,
            "count": len(P),
            "platforms": [{"id": pid, "name": c["name"], "category": c["category"]} for pid, c in P.items()],
        },
        "email": {
            "categories": EMAIL_CATEGORIES,
            "count": len(EMAIL_P),
            "platforms": [{"id": pid, "name": c["name"], "category": c["category"]} for pid, c in EMAIL_P.items()],
        },
    }
