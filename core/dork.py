"""Multi-engine search dorking engine for WebForge."""

from __future__ import annotations

import os
import re
import time
import urllib.parse
import concurrent.futures
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional

import httpx
from bs4 import BeautifulSoup

DEFAULT_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
]

_UA_IDX = 0


def _next_ua() -> str:
    global _UA_IDX
    ua = DEFAULT_USER_AGENTS[_UA_IDX % len(DEFAULT_USER_AGENTS)]
    _UA_IDX += 1
    return ua


def _headers() -> dict:
    return {
        "User-Agent": _next_ua(),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Cache-Control": "no-cache",
    }


ENGINE_LABELS = {
    "ddg": "DuckDuckGo",
    "bing": "Bing",
    "brave": "Brave",
    "google_cse": "Google CSE",
}


def _normalize_url(raw: str) -> str:
    raw = raw.strip()
    if raw.startswith("//"):
        raw = "https:" + raw
    try:
        parsed = urllib.parse.urlparse(raw)
        qs = urllib.parse.parse_qsl(parsed.query)
        qs = [
            (k, v)
            for k, v in qs
            if not k.startswith("utm_") and k not in ("fbclid", "gclid", "mc_cid", "mc_eid", "ref")
        ]
        query = urllib.parse.urlencode(qs)
        return urllib.parse.urlunparse((parsed.scheme, parsed.netloc.lower(), parsed.path.rstrip("/") or "/", parsed.params, query, ""))
    except Exception:
        return raw


def _dedup(results: list[dict]) -> list[dict]:
    seen = set()
    out = []
    for r in results:
        key = _normalize_url(r.get("url", ""))
        if not key or key in seen:
            continue
        seen.add(key)
        out.append({**r, "url": key})
    return out


def _decode_ddg_redirect(href: str) -> Optional[str]:
    q = urllib.parse.parse_qs(urllib.parse.urlparse(href).query)
    uddg = q.get("uddg")
    if uddg:
        return urllib.parse.unquote(uddg[0])
    return None


def _search_ddg(client: httpx.Client, query: str, limit: int) -> list[dict]:
    results: list[dict] = []
    errors: list[str] = []
    for base in ("https://html.duckduckgo.com/html/?q=", "https://lite.duckduckgo.com/lite/?q="):
        try:
            r = client.get(base + urllib.parse.quote_plus(query), headers=_headers(), timeout=18, follow_redirects=True)
            if r.status_code != 200:
                errors.append(f"DuckDuckGo returned HTTP {r.status_code}")
                continue
            if "anomaly" in r.text.lower() or len(r.text) < 2000:
                errors.append("DuckDuckGo bot detection blocked the query")
                continue
            soup = BeautifulSoup(r.text, "html.parser")
            blocks = soup.select("div.result")
            if blocks:
                for b in blocks:
                    a = b.select_one("a.result__a")
                    if not a:
                        continue
                    href = a.get("href", "")
                    url = _decode_ddg_redirect(href) or href
                    if not url or url == "https://duckduckgo.com/":
                        continue
                    sn = b.select_one(".result__snippet")
                    results.append(
                        {
                            "title": a.get_text(" ", strip=True),
                            "url": url,
                            "snippet": sn.get_text(" ", strip=True) if sn else "",
                            "engine": "ddg",
                        }
                    )
            else:
                for a in soup.find_all("a", href=True):
                    href = a.get("href", "")
                    if not href.startswith("//duckduckgo.com/l/"):
                        continue
                    url = _decode_ddg_redirect(href)
                    if not url:
                        continue
                    results.append(
                        {
                            "title": a.get_text(" ", strip=True),
                            "url": url,
                            "snippet": "",
                            "engine": "ddg",
                        }
                    )
        except Exception as e:
            errors.append(str(e))
        if results:
            break
    if not results and errors:
        raise RuntimeError(errors[0])
    return _dedup(results)[:limit]


def _search_bing(client: httpx.Client, query: str, limit: int) -> list[dict]:
    r = client.get(
        "https://www.bing.com/search",
        params={"q": query, "format": "rss", "count": min(limit, 30), "setlang": "en"},
        headers=_headers(),
        timeout=18,
        follow_redirects=True,
    )
    r.raise_for_status()
    items = re.findall(r"<item>(.*?)</item>", r.text, re.S)
    results = []
    for item in items:
        link = re.search(r"<link>(.*?)</link>", item, re.S)
        title = re.search(r"<title>(.*?)</title>", item, re.S)
        desc = re.search(r"<description>(.*?)</description>", item, re.S)
        if not link:
            continue
        url = link.group(1).strip()
        if not url.startswith("http"):
            continue
        url = url.replace("&amp%3B", "&").replace("&amp;", "&")
        def clean(s):
            return (s or "").replace("&amp;", "&").replace("&lt;", "<").replace("&gt;", ">").strip()
        results.append(
            {
                "title": clean(title.group(1) if title else url),
                "url": url,
                "snippet": clean(desc.group(1) if desc else ""),
                "engine": "bing",
            }
        )
    return _dedup(results)[:limit]


def _search_google_cse(client: httpx.Client, query: str, limit: int) -> list[dict]:
    key = os.environ.get("GOOGLE_CSE_KEY") or os.environ.get("WEBFORGE_GOOGLE_CSE_KEY")
    cx = os.environ.get("GOOGLE_CSE_ID") or os.environ.get("WEBFORGE_GOOGLE_CSE_ID")
    if not key or not cx:
        raise RuntimeError("Google CSE requires GOOGLE_CSE_KEY and GOOGLE_CSE_ID env vars")
    r = client.get(
        "https://www.googleapis.com/customsearch/v1",
        params={"key": key, "cx": cx, "q": query, "num": min(limit, 10)},
        timeout=18,
    )
    r.raise_for_status()
    data = r.json()
    items = data.get("items", [])
    results = [
        {
            "title": it.get("title", ""),
            "url": it.get("link", ""),
            "snippet": it.get("snippet", ""),
            "engine": "google_cse",
        }
        for it in items
        if it.get("link")
    ]
    return _dedup(results)[:limit]


def _search_brave(client: httpx.Client, query: str, limit: int) -> list[dict]:
    r = client.get(
        "https://search.brave.com/search",
        params={"q": query, "source": "web"},
        headers=_headers(),
        timeout=18,
        follow_redirects=True,
    )
    r.raise_for_status()
    if r.status_code != 200 or "brave-search" not in r.text and len(r.text) < 4000:
        raise RuntimeError("Brave returned a challenge page")
    soup = BeautifulSoup(r.text, "html.parser")
    results = []
    for b in soup.select("div.snippet"):
        a = b.select_one("a.title")
        if not a:
            continue
        url = a.get("href", "")
        sn = b.select_one("div.snippet-description") or b.select_one("p")
        results.append(
            {
                "title": a.get_text(" ", strip=True),
                "url": url,
                "snippet": sn.get_text(" ", strip=True) if sn else "",
                "engine": "brave",
            }
        )
    if not results:
        raise RuntimeError("Brave returned no parseable results (likely bot protection)")
    return _dedup(results)[:limit]


_ENGINE_FUNCS = {
    "ddg": _search_ddg,
    "bing": _search_bing,
    "brave": _search_brave,
    "google_cse": _search_google_cse,
}

VALID_ENGINES = list(_ENGINE_FUNCS.keys())


def run_dorks(
    query: str,
    engines: Optional[list[str]] = None,
    limit: int = 20,
    target: Optional[str] = None,
) -> dict:
    query = (query or "").strip()
    if not query:
        return {"success": False, "error": "Query is empty"}
    if target:
        target = target.strip().strip("/")
        if "{" in query:
            query = query.replace("{target}", target).replace("{domain}", target)
        elif "site:" not in query.lower():
            query = f"site:{target} {query}"
    if engines:
        engines = [e for e in engines if e in _ENGINE_FUNCS] or ["ddg", "bing"]
    else:
        engines = ["ddg", "bing"]
    limit = max(1, min(int(limit or 20), 100))

    engine_status: dict[str, dict] = {}
    results: list[dict] = []
    start = time.time()

    def run_one(engine: str) -> tuple[str, list[dict], Optional[str]]:
        try:
            with httpx.Client() as client:
                hits = _ENGINE_FUNCS[engine](client, query, limit)
            return engine, hits, None
        except Exception as e:
            return engine, [], str(e)

    with ThreadPoolExecutor(max_workers=min(len(engines), 4)) as ex:
        futures = {ex.submit(run_one, e): e for e in engines}
        for fut in as_completed(futures, timeout=35):
            engine = futures[fut]
            try:
                name, hits, err = fut.result()
            except concurrent.futures.TimeoutError:
                name, hits, err = engine, [], "timed out"
            engine_status[name] = (
                {"status": "ok", "count": len(hits)} if not err else {"status": "error", "message": err}
            )
            results.extend(hits)

    results = _dedup(results)
    return {
        "success": True,
        "query": query,
        "target": target,
        "engines": engine_status,
        "results": results[:limit],
        "total": len(results),
        "elapsed_ms": int((time.time() - start) * 1000),
    }


DORK_LIBRARY = [
    {
        "category": "Admin Panels & Portals",
        "icon": "lock",
        "dorks": [
            {"name": "Login portals", "query": 'intitle:"login" inurl:admin'},
            {"name": "Admin login pages", "query": 'inurl:login "admin" intitle:admin'},
            {"name": "Webmin admin panels", "query": 'intitle:"webmin" inurl:10000'},
            {"name": "phpMyAdmin logins", "query": 'intitle:phpmyadmin "login"'},
            {"name": "WordPress admin", "query": 'inurl:wp-admin intitle:login'},
            {"name": "Joomla admin", "query": 'inurl:/administrator intitle:joomla'},
            {"name": "Drupal login", "query": 'inurl:/user/login intitle:drupal'},
        ],
    },
    {
        "category": "Open Directories",
        "icon": "folder",
        "dorks": [
            {"name": "Index of root", "query": 'intitle:"index of" "/"'},
            {"name": "Index of backups", "query": 'intitle:"index of" backup'},
            {"name": "Index of configs", "query": 'intitle:"index of" config'},
            {"name": "Index of uploads", "query": 'intitle:"index of" uploads'},
            {"name": "Index of logs", "query": 'intitle:"index of" log'},
            {"name": "Parent directory listing", "query": 'intitle:"index of" "parent directory"'},
            {"name": "Index of private", "query": 'intitle:"index of" private'},
        ],
    },
    {
        "category": "Exposed Files",
        "icon": "file",
        "dorks": [
            {"name": "PDF documents", "query": "filetype:pdf confidential"},
            {"name": "Excel spreadsheets", "query": "filetype:xls password"},
            {"name": "Word documents", "query": "filetype:doc classified"},
            {"name": "Text / note files", "query": "filetype:txt password"},
            {"name": "Emails & contact lists", "query": "filetype:eml intext:password"},
            {"name": "Backup archives", "query": "filetype:zip intext:backup"},
            {"name": "Database dumps", "query": "filetype:sql \"insert into\""},
        ],
    },
    {
        "category": "Sensitive Data",
        "icon": "key",
        "dorks": [
            {"name": "Exposed passwords", "query": "intext:password intext:username"},
            {"name": "API keys", "query": 'intext:"api_key" OR intext:"apikey"'},
            {"name": "AWS keys", "query": 'intext:"AKIA"'},
            {"name": "Private keys", "query": 'filetype:pem "BEGIN RSA PRIVATE KEY"'},
            {"name": "Config with credentials", "query": "intext:password filetype:conf"},
            {"name": "Email with credentials", "query": 'intext:"@gmail.com" intext:password'},
        ],
    },
    {
        "category": "Code & Config",
        "icon": "code",
        "dorks": [
            {"name": "Git config files", "query": 'inurl:.git intext:repositoryformatversion'},
            {"name": "Env files", "query": "filetype:env APP_KEY"},
            {"name": "wp-config.php", "query": 'intitle:"index of" "wp-config.php"'},
            {"name": "PHP source", "query": "filetype:php inurl:index"},
            {"name": "Jenkins / CI config", "query": "inurl:jenkins intext:console"},
            {"name": "Exposed YAML configs", "query": "filetype:yaml secrets"},
            {"name": "Docker configs", "query": "filetype:yml docker-compose"},
        ],
    },
    {
        "category": "Vulnerable Servers",
        "icon": "alert",
        "dorks": [
            {"name": "phpinfo pages", "query": "intitle:phpinfo PHP Version"},
            {"name": "Tomcat manager", "query": "inurl:manager/html intitle:tomcat"},
            {"name": "Jenkins dashboard", "query": "intitle:jenkins dashboard"},
            {"name": "Kibana dashboards", "query": 'intitle:"kibana" "loading"'},
            {"name": "Grafana login", "query": 'intitle:grafana "Sign in"'},
            {"name": "Solr admin", "query": "inurl:solr intitle:admin"},
        ],
    },
    {
        "category": "Tech Stack Discovery",
        "icon": "chip",
        "dorks": [
            {"name": "Server version", "query": 'intitle:"Apache Server" intext:"server at"'},
            {"name": "Powered by tags", "query": 'intext:"powered by wordpress"'},
            {"name": "nginx server", "query": 'intext:"welcome to nginx!"'},
            {"name": "IIS default", "query": 'intitle:"IIS7" "Welcome"'},
            {"name": "Laravel default", "query": 'intext:"Laravel v" intext:"PHP v"'},
        ],
    },
    {
        "category": "Error & Debug Pages",
        "icon": "bug",
        "dorks": [
            {"name": "Stack traces", "query": 'intitle:"php error" intext:"Fatal error"'},
            {"name": "Debug enabled", "query": 'intext:"debug=true" inurl:admin'},
            {"name": "SQL errors", "query": 'intext:"You have an error in your SQL syntax"'},
            {"name": "Verbose errors", "query": 'intitle:"Warning" intext:"include" inurl:php'},
            {"name": "PHP warnings", "query": 'intext:"PHP Warning" filetype:php'},
        ],
    },
]


def get_dork_library() -> list[dict]:
    return DORK_LIBRARY
