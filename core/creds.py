"""SQLite-backed credential store shared across brute force, spray and enum modules."""

from __future__ import annotations

import sqlite3
import time
from pathlib import Path
from typing import Optional

from webforg.core.config import get_settings

# Centralized path (env-overridable via WEBFORGE_CREDS_DB_PATH / WEBFORGE_DATA_DIR);
# default matches the historical `~/.webforg/creds.db`.
DB_PATH = get_settings().creds_db_path


def get_conn() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("""
        CREATE TABLE IF NOT EXISTS credentials (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT NOT NULL DEFAULT '',
            username TEXT NOT NULL,
            password TEXT NOT NULL DEFAULT '',
            source TEXT NOT NULL DEFAULT 'manual',
            extra TEXT NOT NULL DEFAULT '',
            created_at REAL NOT NULL
        )
    """)
    conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_creds_unique ON credentials(target, username, password)")
    return conn


def add_cred(target: str, username: str, password: str, source: str = "manual", extra: str = "") -> bool:
    """Insert a single credential (deduped). Returns True if newly added."""
    conn = get_conn()
    try:
        cur = conn.execute(
            "INSERT OR IGNORE INTO credentials (target, username, password, source, extra, created_at) VALUES (?,?,?,?,?,?)",
            (target or "", username or "", password or "", source, extra, time.time()),
        )
        conn.commit()
        return cur.rowcount > 0
    finally:
        conn.close()


def add_creds(entries: list[dict]) -> int:
    """Bulk insert. Each dict: target, username, password, source, extra. Returns count added."""
    if not entries:
        return 0
    conn = get_conn()
    added = 0
    try:
        now = time.time()
        for e in entries:
            cur = conn.execute(
                "INSERT OR IGNORE INTO credentials (target, username, password, source, extra, created_at) VALUES (?,?,?,?,?,?)",
                (e.get("target") or "", e.get("username") or "", e.get("password") or "",
                 e.get("source") or "import", e.get("extra") or "", now),
            )
            added += cur.rowcount
        conn.commit()
        return added
    finally:
        conn.close()


def list_creds(limit: int = 500) -> list[dict]:
    conn = get_conn()
    try:
        rows = conn.execute(
            "SELECT * FROM credentials ORDER BY created_at DESC, id DESC LIMIT ?", (limit,)
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def search_creds(query: str, limit: int = 500) -> list[dict]:
    conn = get_conn()
    try:
        like = f"%{query}%"
        rows = conn.execute(
            """SELECT * FROM credentials
               WHERE target LIKE ? OR username LIKE ? OR password LIKE ?
               ORDER BY created_at DESC, id DESC LIMIT ?""",
            (like, like, like, limit),
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def delete_cred(cred_id: int) -> bool:
    conn = get_conn()
    try:
        cur = conn.execute("DELETE FROM credentials WHERE id = ?", (cred_id,))
        conn.commit()
        return cur.rowcount > 0
    finally:
        conn.close()


def clear_creds() -> int:
    conn = get_conn()
    try:
        cur = conn.execute("DELETE FROM credentials")
        conn.commit()
        return cur.rowcount
    finally:
        conn.close()


def count_creds() -> int:
    conn = get_conn()
    try:
        return conn.execute("SELECT COUNT(*) AS c FROM credentials").fetchone()["c"]
    finally:
        conn.close()


def extract_creds_from_result(url: str, result: dict) -> list[dict]:
    """Walk a module result dict and pull username/password pairs from common shapes."""
    found = []
    seen = set()
    candidates: list[dict] = []
    for key in ("found", "credentials", "creds", "successful", "hits"):
        val = result.get(key)
        if isinstance(val, list):
            candidates.extend(val)
    if isinstance(result.get("results"), list):
        for r in result["results"]:
            if isinstance(r, dict) and r.get("status") in ("FOUND", "success", "SUCCESS", "VALID"):
                candidates.append(r)
    for c in candidates:
        if not isinstance(c, dict):
            continue
        user = c.get("username") or c.get("user") or c.get("email") or ""
        pwd = c.get("password") or c.get("pass") or ""
        if not user:
            continue
        key = (user, pwd)
        if key in seen:
            continue
        seen.add(key)
        found.append({
            "target": url,
            "username": str(user),
            "password": str(pwd),
            "source": (c.get("status") or "found"),
            "extra": str(c.get("details") or "")[:300],
        })
    return found
