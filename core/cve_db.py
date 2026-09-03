"""CVE database synchronization — fetches from NVD + CISA KEV + Sploitus.com."""

from __future__ import annotations
import json
import re
import sqlite3
import time
import xml.etree.ElementTree as ET
from pathlib import Path
from datetime import datetime, timedelta, timezone
from typing import Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
import httpx

from webforg.core.config import get_settings

# Centralized path (env-overridable via WEBFORGE_CVE_DB_PATH / WEBFORGE_DATA_DIR);
# default matches the historical `~/.webforg/cve_index.db`.
DB_PATH = get_settings().cve_db_path

SPLOITUS_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
}


def get_db() -> sqlite3.Connection:
    """Get or create the CVE database."""
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH))
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("""
        CREATE TABLE IF NOT EXISTS cves (
            id TEXT PRIMARY KEY,
            description TEXT,
            cvss_score REAL,
            severity TEXT,
            published_date TEXT,
            last_modified TEXT,
            affected_vendor TEXT,
            affected_product TEXT,
            exploit_available INTEGER DEFAULT 0,
            module_path TEXT,
            cisa_kev INTEGER DEFAULT 0,
            source TEXT DEFAULT 'nvd',
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS sploitus_exploits (
            id TEXT PRIMARY KEY,
            title TEXT,
            cve_id TEXT,
            cvss_score REAL,
            published_date TEXT,
            source_url TEXT,
            exploit_source TEXT,
            description TEXT,
            raw_code TEXT,
            exploit_type TEXT,
            tags TEXT,
            fetched_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS metadata (
            key TEXT PRIMARY KEY,
            value TEXT
        )
    """)
    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_sploitus_cve ON sploitus_exploits(cve_id)
    """)
    conn.commit()
    return conn


# ========== NVD ==========

def fetch_nvd_recent(days: int = 30, page_size: int = 200) -> list[dict]:
    """Fetch recent CVEs from NVD API 2.0 with pagination."""
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    start_date = (datetime.now(timezone.utc) - timedelta(days=days)).strftime("%Y-%m-%dT00:00:00.000")
    end_date = datetime.now(timezone.utc).strftime("%Y-%m-%dT23:59:59.000")

    all_results = []
    start_index = 0

    while True:
        params = {
            "pubStartDate": start_date,
            "pubEndDate": end_date,
            "resultsPerPage": page_size,
            "startIndex": start_index,
        }

        try:
            resp = httpx.get(url, params=params, timeout=30)
            if resp.status_code == 403:
                print(f"  [!] NVD rate limited, waiting 6s...")
                time.sleep(6)
                continue
            if resp.status_code != 200:
                print(f"  [!] NVD returned {resp.status_code}")
                break

            data = resp.json()
            vulnerabilities = data.get("vulnerabilities", [])
            total = data.get("totalResults", 0)

            for vuln in vulnerabilities:
                cve_data = vuln.get("cve", {})
                metrics = cve_data.get("metrics", {})
                cvss_v3 = metrics.get("cvssMetricV31", [{}])
                if cvss_v3:
                    cvss_info = cvss_v3[0].get("cvssData", {})
                else:
                    cvss_info = metrics.get("cvssMetricV40", [{}])
                    cvss_info = cvss_info[0].get("cvssData", {}) if cvss_info else {}

                all_results.append({
                    "id": cve_data.get("id"),
                    "description": cve_data.get("descriptions", [{}])[0].get("value", ""),
                    "cvss_score": cvss_info.get("baseScore"),
                    "severity": cvss_info.get("baseSeverity"),
                    "published_date": cve_data.get("published"),
                    "last_modified": cve_data.get("lastModified"),
                    "source": "nvd",
                })

            start_index += len(vulnerabilities)
            if start_index >= total or len(vulnerabilities) == 0:
                break

            time.sleep(0.7)

        except Exception as e:
            print(f"  [!] NVD fetch error: {e}")
            break

    return all_results


# ========== CISA KEV ==========

def fetch_cisa_kev() -> list[dict]:
    """Fetch CISA Known Exploited Vulnerabilities catalog."""
    url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

    try:
        resp = httpx.get(url, timeout=30)
        if resp.status_code == 200:
            data = resp.json()
            vulns = data.get("vulnerabilities", [])
            results = []
            for vuln in vulns:
                results.append({
                    "id": vuln.get("cveID"),
                    "description": vuln.get("shortDescription", ""),
                    "cvss_score": None,
                    "severity": "CRITICAL",
                    "published_date": vuln.get("dateAdded"),
                    "vendor": vuln.get("vendorProject"),
                    "product": vuln.get("product"),
                    "source": "cisa_kev",
                })
            return results
    except Exception as e:
        print(f"  [!] CISA KEV fetch error: {e}")

    return []


# ========== Sploitus.com ==========

def fetch_sploitus_rss(max_items: int = 200) -> list[dict]:
    """Fetch CVE exploit entries from Sploitus RSS feed."""
    url = "https://sploitus.com/rss"
    results = []

    try:
        resp = httpx.get(url, timeout=30, headers=SPLOITUS_HEADERS)
        if resp.status_code != 200:
            print(f"  [!] Sploitus RSS returned {resp.status_code}")
            return []

        root = ET.fromstring(resp.text)

        for item in root.iter("item"):
            title_el = item.find("title")
            link_el = item.find("link")
            guid_el = item.find("guid")
            pub_el = item.find("pubDate")

            title = title_el.text if title_el is not None else ""
            link = link_el.text if link_el is not None else ""
            guid = guid_el.text if guid_el is not None else ""
            pub_date = pub_el.text if pub_el is not None else ""

            if not title:
                continue

            cve_match = re.search(r'(CVE-\d{4}-\d{4,})', title, re.IGNORECASE)

            results.append({
                "id": guid,
                "title": title,
                "cve_id": cve_match.group(1).upper() if cve_match else None,
                "link": link,
                "published_date": pub_date,
            })

            if len(results) >= max_items:
                break

    except Exception as e:
        print(f"  [!] Sploitus RSS error: {e}")

    return results


def scrape_sploitus_exploit(exploit_id: str, retries: int = 2) -> Optional[dict]:
    """Scrape a single exploit page from Sploitus for full details + source code."""
    url = f"https://sploitus.com/exploit?id={exploit_id}"

    for attempt in range(retries + 1):
        try:
            resp = httpx.get(url, timeout=20, headers=SPLOITUS_HEADERS, follow_redirects=True)
            if resp.status_code == 403:
                time.sleep(2)
                continue
            if resp.status_code != 200:
                return None

            html = resp.text

            title_match = re.search(r'<h1[^>]*>(.*?)</h1>', html, re.DOTALL)
            title = title_match.group(1).strip() if title_match else ""
            title = re.sub(r'<[^>]+>', '', title).strip()

            cvss_match = re.search(r'CVSS\s+([\d.]+)', html)
            cvss = float(cvss_match.group(1)) if cvss_match else None

            date_match = re.search(r'(\d{4}-\d{2}-\d{2})\s*\|', html)
            pub_date = date_match.group(1) if date_match else None

            cve_match = re.search(r'(CVE-\d{4}-\d{4,})', title + " " + html, re.IGNORECASE)
            cve_id = cve_match.group(1).upper() if cve_match else None

            code_blocks = re.findall(
                r'<pre[^>]*><code[^>]*>(.*?)</code></pre>',
                html, re.DOTALL
            )
            raw_code = ""
            if code_blocks:
                raw_code = max(code_blocks, key=len)
                raw_code = re.sub(r'<[^>]+>', '', raw_code)
                raw_code = (raw_code
                    .replace('&amp;', '&')
                    .replace('&lt;', '<')
                    .replace('&gt;', '>')
                    .replace('&quot;', '"')
                    .replace('&#39;', "'")
                    .replace('&nbsp;', ' '))
            else:
                code_match = re.search(r'```[\w]*\n(.*?)```', html, re.DOTALL)
                raw_code = code_match.group(1).strip() if code_match else ""

            paragraphs = re.findall(r'<p[^>]*>(.*?)</p>', html, re.DOTALL)
            description = ""
            for p in paragraphs:
                cleaned = re.sub(r'<[^>]+>', '', p).strip()
                if len(cleaned) > 30:
                    description = cleaned
                    break

            exploit_type = "unknown"
            lower_html = html.lower()
            if "metasploit" in lower_html and "module" in lower_html:
                exploit_type = "metasploit"
            elif "python" in lower_html and ("exploit" in lower_html or "poc" in lower_html or "requests" in lower_html):
                exploit_type = "python"
            elif "ruby" in lower_html and "exploit" in lower_html:
                exploit_type = "ruby"
            elif "nmap" in lower_html or "nuclei" in lower_html:
                exploit_type = "scanner"
            elif "bash" in lower_html or "shell" in lower_html or "/bin/sh" in lower_html:
                exploit_type = "shell"
            elif "php" in lower_html and ("shell" in lower_html or "exploit" in lower_html):
                exploit_type = "php"
            elif "java" in lower_html and ("deserialization" in lower_html or "rce" in lower_html):
                exploit_type = "java"

            return {
                "id": exploit_id,
                "title": title,
                "cve_id": cve_id,
                "cvss_score": cvss,
                "published_date": pub_date,
                "source_url": url,
                "exploit_source": "sploitus",
                "description": description[:2000],
                "raw_code": raw_code[:10000],
                "exploit_type": exploit_type,
            }

        except Exception as e:
            if attempt < retries:
                time.sleep(2)
            else:
                return None

    return None


def fetch_sploitus_all(pages: int = 5, max_workers: int = 8) -> list[dict]:
    """Fetch exploits from Sploitus RSS + scrape detail pages for CVEs."""
    print("  [*] Fetching Sploitus RSS feed...")
    rss_entries = fetch_sploitus_rss(max_items=pages * 30)
    print(f"  [+] Got {len(rss_entries)} entries from RSS")

    cve_entries = [e for e in rss_entries if e.get("cve_id")]
    non_cve = [e for e in rss_entries if not e.get("cve_id")]
    print(f"  [*] {len(cve_entries)} CVE entries, {len(non_cve)} non-CVE tools")

    to_scrape = []
    seen_ids = set()
    for entry in cve_entries[:150]:
        eid = entry["id"]
        if eid not in seen_ids:
            seen_ids.add(eid)
            to_scrape.append(entry)

    for entry in non_cve[:80]:
        eid = entry["id"]
        if eid not in seen_ids:
            seen_ids.add(eid)
            to_scrape.append(entry)

    print(f"  [*] Scraping {len(to_scrape)} exploit detail pages (workers={max_workers})...")

    scraped = []
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {}
        for entry in to_scrape:
            f = executor.submit(scrape_sploitus_exploit, entry["id"])
            futures[f] = entry

        done = 0
        for future in as_completed(futures):
            done += 1
            if done % 25 == 0:
                print(f"    ... scraped {done}/{len(to_scrape)}")
            result = future.result()
            if result:
                scraped.append(result)

    print(f"  [+] Successfully scraped {len(scraped)} exploit pages")

    return scraped


# ========== Database Update ==========

def update_cve_database(nvd_days: int = 90, sploitus_pages: int = 5) -> None:
    """Main update function — fetches and stores CVEs from all sources."""
    print("[*] Updating CVE database...")
    conn = get_db()
    cursor = conn.cursor()

    print("\n[*] === NVD ===")
    print("  [*] Fetching recent CVEs from NVD...")
    nvd_cves = fetch_nvd_recent(days=nvd_days)
    print(f"  [+] Got {len(nvd_cves)} CVEs from NVD")

    for cve in nvd_cves:
        cursor.execute("""
            INSERT OR REPLACE INTO cves
                (id, description, cvss_score, severity, published_date, last_modified, source, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
        """, (
            cve["id"], cve["description"], cve["cvss_score"],
            cve["severity"], cve["published_date"], cve["last_modified"],
            cve["source"],
        ))

    print("\n[*] === CISA KEV ===")
    print("  [*] Fetching CISA KEV catalog...")
    kev_cves = fetch_cisa_kev()
    print(f"  [+] Got {len(kev_cves)} CVEs from CISA KEV")

    for cve in kev_cves:
        cursor.execute("""
            UPDATE cves SET cisa_kev = 1, affected_vendor = ?, affected_product = ?
            WHERE id = ?
        """, (cve.get("vendor"), cve.get("product"), cve["id"]))

        cursor.execute("""
            INSERT OR IGNORE INTO cves
                (id, description, severity, published_date, cisa_kev, affected_vendor, affected_product, source, updated_at)
            VALUES (?, ?, ?, ?, 1, ?, ?, ?, CURRENT_TIMESTAMP)
        """, (
            cve["id"], cve["description"], cve["severity"],
            cve["published_date"], cve.get("vendor"), cve.get("product"),
            cve["source"],
        ))

    print("\n[*] === Sploitus.com ===")
    sploitus_exploits = fetch_sploitus_all(pages=sploitus_pages)

    exploit_count = 0
    for exploit in sploitus_exploits:
        cursor.execute("""
            INSERT OR REPLACE INTO sploitus_exploits
                (id, title, cve_id, cvss_score, published_date, source_url,
                 exploit_source, description, raw_code, exploit_type, fetched_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
        """, (
            exploit["id"], exploit["title"], exploit["cve_id"],
            exploit["cvss_score"], exploit.get("published_date"),
            exploit["source_url"], exploit["exploit_source"],
            exploit["description"], exploit["raw_code"],
            exploit["exploit_type"],
        ))

        if exploit.get("cve_id"):
            cursor.execute("""
                UPDATE cves SET exploit_available = 1 WHERE id = ?
            """, (exploit["cve_id"],))

            cursor.execute("""
                INSERT OR IGNORE INTO cves
                    (id, description, cvss_score, severity, exploit_available, source, updated_at)
                VALUES (?, ?, ?, ?, 1, 'sploitus', CURRENT_TIMESTAMP)
            """, (
                exploit["cve_id"], exploit.get("description", ""),
                exploit.get("cvss_score"),
                "CRITICAL" if exploit.get("cvss_score", 0) and exploit["cvss_score"] >= 9.0
                else "HIGH" if exploit.get("cvss_score", 0) and exploit["cvss_score"] >= 7.0
                else "MEDIUM" if exploit.get("cvss_score", 0) and exploit["cvss_score"] >= 4.0
                else None,
            ))

        exploit_count += 1

    cursor.execute(
        "INSERT OR REPLACE INTO metadata (key, value) VALUES (?, ?)",
        ("last_updated", datetime.now(timezone.utc).isoformat())
    )
    cursor.execute(
        "INSERT OR REPLACE INTO metadata (key, value) VALUES (?, ?)",
        ("sploitus_exploit_count", str(exploit_count))
    )

    conn.commit()
    conn.close()

    print(f"\n[green][+] Database updated:[/]")
    print(f"  NVD:     {len(nvd_cves)} CVEs")
    print(f"  CISA KEV: {len(kev_cves)} entries")
    print(f"  Sploitus: {exploit_count} exploits (with source code)")


# ========== Search ==========

def search_cves(query: str, min_cvss: float = 0.0, limit: int = 50) -> list[dict]:
    """Search the local CVE database."""
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT id, description, cvss_score, severity, published_date,
               cisa_kev, affected_vendor, affected_product, exploit_available
        FROM cves
        WHERE (id LIKE ? OR description LIKE ? OR affected_vendor LIKE ? OR affected_product LIKE ?)
          AND (cvss_score IS NULL OR cvss_score >= ?)
        ORDER BY cisa_kev DESC, cvss_score DESC NULLS LAST
        LIMIT ?
    """, (f"%{query}%", f"%{query}%", f"%{query}%", f"%{query}%", min_cvss, limit))

    rows = cursor.fetchall()
    conn.close()

    return [
        {
            "id": r[0],
            "description": r[1],
            "cvss": r[2],
            "severity": r[3],
            "published": r[4],
            "cisa_kev": bool(r[5]),
            "vendor": r[6],
            "product": r[7],
            "exploit_available": bool(r[8]),
        }
        for r in rows
    ]


def search_sploitus_exploits(query: str = "", cve_id: str = "", limit: int = 50) -> list[dict]:
    """Search Sploitus exploits in local DB."""
    conn = get_db()
    cursor = conn.cursor()

    conditions = []
    params = []

    if cve_id:
        # Support partial CVE IDs (e.g., "CVE-2020-35" matches "CVE-2020-35452")
        if len(cve_id) < 15:
            conditions.append("cve_id LIKE ?")
            params.append(f"%{cve_id.upper()}%")
        else:
            conditions.append("cve_id = ?")
            params.append(cve_id.upper())
    if query:
        conditions.append("(title LIKE ? OR description LIKE ? OR raw_code LIKE ?)")
        params.extend([f"%{query}%", f"%{query}%", f"%{query}%"])

    where = " AND ".join(conditions) if conditions else "1=1"
    params.append(limit)

    cursor.execute(f"""
        SELECT id, title, cve_id, cvss_score, published_date, source_url,
               exploit_source, description, raw_code, exploit_type
        FROM sploitus_exploits
        WHERE {where}
        ORDER BY cvss_score DESC NULLS LAST
        LIMIT ?
    """, params)

    rows = cursor.fetchall()
    conn.close()

    return [
        {
            "id": r[0],
            "title": r[1],
            "cve_id": r[2],
            "cvss": r[3],
            "published": r[4],
            "source_url": r[5],
            "source": r[6],
            "description": r[7],
            "code": r[8],
            "type": r[9],
        }
        for r in rows
    ]


def get_sploitus_stats() -> dict:
    """Get Sploitus exploit statistics."""
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) FROM sploitus_exploits")
    total = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(DISTINCT cve_id) FROM sploitus_exploits WHERE cve_id IS NOT NULL")
    unique_cves = cursor.fetchone()[0]

    cursor.execute("SELECT exploit_type, COUNT(*) FROM sploitus_exploits GROUP BY exploit_type")
    by_type = {r[0]: r[1] for r in cursor.fetchall()}

    cursor.execute("SELECT fetched_at FROM sploitus_exploits ORDER BY fetched_at DESC LIMIT 1")
    last_fetch = cursor.fetchone()
    last_fetch = last_fetch[0] if last_fetch else None

    conn.close()

    return {
        "total_exploits": total,
        "unique_cves": unique_cves,
        "by_type": by_type,
        "last_fetch": last_fetch,
    }


def get_sploitus_exploits_for_target(
    technologies: list[str] = None,
    cve_ids: list[str] = None,
    cms: str = "",
    limit: int = 30,
) -> list[dict]:
    """Query Sploitus DB for exploits matching target's technologies and CVEs.
    
    Searches by:
    - Direct CVE ID matches
    - Technology keyword matches in title/description/code
    - CMS-specific exploits (wordpress, joomla, drupal, etc.)
    
    Returns exploits sorted by CVSS score, filtered to only those with raw_code.
    """
    conn = get_db()
    cursor = conn.cursor()
    
    conditions = []
    params = []
    
    # CVE ID matches
    if cve_ids:
        placeholders = ",".join(["?" for _ in cve_ids])
        conditions.append(f"cve_id IN ({placeholders})")
        params.extend([c.upper() for c in cve_ids])
    
    # Technology keyword matches
    tech_conditions = []
    if cms:
        tech_conditions.append("(title LIKE ? OR description LIKE ? OR raw_code LIKE ?)")
        params.extend([f"%{cms}%", f"%{cms}%", f"%{cms}%"])
    
    if technologies:
        for tech in technologies[:10]:
            clean = tech.split(":")[-1].strip()
            if len(clean) >= 3:
                tech_conditions.append("(title LIKE ? OR description LIKE ? OR raw_code LIKE ?)")
                params.extend([f"%{clean}%", f"%{clean}%", f"%{clean}%"])
    
    if tech_conditions:
        conditions.append("(" + " OR ".join(tech_conditions) + ")")
    
    # Only exploits with actual code
    conditions.append("raw_code IS NOT NULL AND raw_code != ''")
    
    where = " AND ".join(conditions) if conditions else "1=1"
    params.append(limit)
    
    cursor.execute(f"""
        SELECT id, title, cve_id, cvss_score, published_date, source_url,
               exploit_source, description, raw_code, exploit_type
        FROM sploitus_exploits
        WHERE {where}
        ORDER BY cvss_score DESC NULLS LAST
        LIMIT ?
    """, params)
    
    rows = cursor.fetchall()
    conn.close()
    
    results = []
    for r in rows:
        results.append({
            "id": r[0],
            "title": r[1],
            "cve_id": r[2],
            "cvss": r[3],
            "published": r[4],
            "source_url": r[5],
            "source": r[6],
            "description": r[7],
            "code": r[8],
            "type": r[9],
        })
    
    return results
