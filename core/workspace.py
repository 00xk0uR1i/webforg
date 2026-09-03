"""Workspace management — persist and restore project state."""

from __future__ import annotations
import json
import sqlite3
import os
from pathlib import Path
from datetime import datetime
from typing import Optional


from webforg.core.config import get_settings

# Centralized path (env-overridable via WEBFORGE_WORKSPACE_DIR / WEBFORGE_DATA_DIR);
# default matches the historical `~/.webforg/workspaces`.
WORKSPACE_DIR = get_settings().workspace_dir


def _safe_workspace_name(name: str) -> str:
    """Validate a workspace name, rejecting anything that could escape the
    workspace directory (path separators, ``..``, empty names).

    Raises ``ValueError`` for unsafe names.  Workspace names map 1:1 to the
    file ``{name}.db`` inside ``WORKSPACE_DIR``, so the name must be a plain
    filename without any path component.
    """
    if not isinstance(name, str) or not name.strip():
        raise ValueError("Workspace name must be a non-empty string")
    name = name.strip()
    if name in (".", "..") or "/" in name or "\\" in name or "\x00" in name:
        raise ValueError(f"Invalid workspace name: {name!r}")
    candidate = (WORKSPACE_DIR / f"{name}.db").resolve()
    try:
        candidate.relative_to(WORKSPACE_DIR.resolve())
    except ValueError:
        raise ValueError(f"Invalid workspace name: {name!r}")
    return name


class Workspace:
    """A named project/workspace storing targets, results, and session data."""
    
    def __init__(self, name: str = "default"):
        self.name = _safe_workspace_name(name)
        self.created_at = datetime.now()
        self.modified_at = datetime.now()
        self.targets: list[dict] = []
        self.results: list[dict] = []
        self.notes: str = ""
        self._db_path = WORKSPACE_DIR / f"{self.name}.db"
    
    def save(self) -> None:
        """Persist workspace to SQLite."""
        WORKSPACE_DIR.mkdir(parents=True, exist_ok=True)
        
        conn = sqlite3.connect(str(self._db_path))
        cursor = conn.cursor()
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS targets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                host TEXT NOT NULL,
                port INTEGER DEFAULT 80,
                ssl INTEGER DEFAULT 0,
                path TEXT DEFAULT '/',
                notes TEXT DEFAULT '',
                fingerprint TEXT DEFAULT '{}',
                added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target_host TEXT,
                module_path TEXT,
                check_result TEXT DEFAULT '{}',
                exploit_result TEXT DEFAULT '{}',
                session_id TEXT,
                ran_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS metadata (
                key TEXT PRIMARY KEY,
                value TEXT
            )
        """)
        
        cursor.execute(
            "INSERT OR REPLACE INTO metadata (key, value) VALUES (?, ?)",
            ("name", self.name)
        )
        cursor.execute(
            "INSERT OR REPLACE INTO metadata (key, value) VALUES (?, ?)",
            ("updated_at", datetime.now().isoformat())
        )
        
        # Write targets
        cursor.execute("DELETE FROM targets")
        for t in self.targets:
            cursor.execute(
                "INSERT INTO targets (host, port, ssl, path, notes, fingerprint) VALUES (?,?,?,?,?,?)",
                (t.get("host"), t.get("port", 80), int(t.get("ssl", False)),
                 t.get("path", "/"), t.get("notes", ""), json.dumps(t.get("fingerprint", {})))
            )
        
        conn.commit()
        conn.close()
        self.modified_at = datetime.now()
    
    def load(self) -> bool:
        """Load workspace from SQLite. Returns False if doesn't exist."""
        if not self._db_path.exists():
            return False
        
        conn = sqlite3.connect(str(self._db_path))
        cursor = conn.cursor()
        
        # Load targets
        try:
            cursor.execute("SELECT host, port, ssl, path, notes, fingerprint FROM targets")
            self.targets = [
                {
                    "host": row[0], "port": row[1], "ssl": bool(row[2]),
                    "path": row[3], "notes": row[4],
                    "fingerprint": json.loads(row[5]) if row[5] else {}
                }
                for row in cursor.fetchall()
            ]
        except sqlite3.OperationalError:
            pass
        
        conn.close()
        return True

    def reset(self) -> None:
        """Clear in-memory state and persist an empty workspace."""
        self.targets = []
        self.results = []
        self.notes = ""
        self.save()

    def export(self) -> dict:
        """Serializable snapshot of this workspace's state."""
        return {
            "name": self.name,
            "targets": list(self.targets),
            "results": list(self.results),
            "notes": self.notes,
            "created_at": self.created_at.isoformat(),
            "modified_at": self.modified_at.isoformat(),
        }


def list_workspaces() -> list[str]:
    """List all available workspace names."""
    if not WORKSPACE_DIR.exists():
        return []
    return [f.stem for f in WORKSPACE_DIR.glob("*.db")]


def delete_workspace(name: str) -> bool:
    """Delete a workspace. Returns False if doesn't exist or name is unsafe."""
    try:
        name = _safe_workspace_name(name)
    except ValueError:
        return False
    path = WORKSPACE_DIR / f"{name}.db"
    if path.exists():
        path.unlink()
        return True
    return False


def workspace_exists(name: str) -> bool:
    """True when a workspace with this (valid) name has a saved state."""
    try:
        name = _safe_workspace_name(name)
    except ValueError:
        return False
    return (WORKSPACE_DIR / f"{name}.db").exists()
