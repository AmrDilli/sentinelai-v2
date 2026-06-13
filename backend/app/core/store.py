"""SQLite-backed case store, so analyses survive a server restart.

Deliberately tiny: one table, JSON blob per analysis. Swappable for Postgres
later by reimplementing this same interface. Thread-safe via a lock + per-call
connections (FastAPI runs handlers across threads).
"""
from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path

from app.config import settings

_LOCK = threading.Lock()


def _conn() -> sqlite3.Connection:
    Path(settings.DB_PATH).parent.mkdir(parents=True, exist_ok=True)
    c = sqlite3.connect(settings.DB_PATH, timeout=30)
    c.row_factory = sqlite3.Row
    return c


def init_db() -> None:
    with _LOCK, _conn() as c:
        c.execute(
            """CREATE TABLE IF NOT EXISTS analyses (
                   id TEXT PRIMARY KEY,
                   user_id TEXT,
                   filename TEXT,
                   module TEXT,
                   status TEXT,
                   progress INTEGER DEFAULT 0,
                   stage TEXT,
                   score INTEGER,
                   severity TEXT,
                   error TEXT,
                   data TEXT,
                   created_at TEXT DEFAULT (datetime('now'))
               )"""
        )
        # Migrate older DBs that predate the user_id column.
        cols = {r["name"] for r in c.execute("PRAGMA table_info(analyses)").fetchall()}
        if "user_id" not in cols:
            c.execute("ALTER TABLE analyses ADD COLUMN user_id TEXT")


def upsert(record: dict) -> None:
    with _LOCK, _conn() as c:
        c.execute(
            """INSERT INTO analyses (id, user_id, filename, module, status, progress, stage,
                                     score, severity, error, data)
               VALUES (:id, :user_id, :filename, :module, :status, :progress, :stage,
                       :score, :severity, :error, :data)
               ON CONFLICT(id) DO UPDATE SET
                   filename=excluded.filename, module=excluded.module,
                   status=excluded.status, progress=excluded.progress,
                   stage=excluded.stage, score=excluded.score,
                   severity=excluded.severity, error=excluded.error,
                   data=excluded.data""",
            {
                "id": record["id"],
                "user_id": record.get("user_id"),
                "filename": record.get("filename"),
                "module": record.get("module"),
                "status": record.get("status"),
                "progress": record.get("progress", 0),
                "stage": record.get("stage"),
                "score": (record.get("report") or {}).get("score"),
                "severity": (record.get("report") or {}).get("severity"),
                "error": record.get("error"),
                "data": json.dumps(record),
            },
        )


def get(analysis_id: str, user_id: str | None = None) -> dict | None:
    """Fetch one analysis. If user_id is given, only return it when it belongs
    to that user (prevents reading other accounts' cases)."""
    with _LOCK, _conn() as c:
        if user_id is None:
            row = c.execute("SELECT data FROM analyses WHERE id=?", (analysis_id,)).fetchone()
        else:
            row = c.execute("SELECT data FROM analyses WHERE id=? AND user_id=?",
                            (analysis_id, user_id)).fetchone()
    return json.loads(row["data"]) if row else None


def list_all(user_id: str | None = None) -> list[dict]:
    with _LOCK, _conn() as c:
        if user_id is None:
            rows = c.execute("SELECT data FROM analyses ORDER BY created_at DESC").fetchall()
        else:
            rows = c.execute("SELECT data FROM analyses WHERE user_id=? ORDER BY created_at DESC",
                             (user_id,)).fetchall()
    return [json.loads(r["data"]) for r in rows]


def delete(analysis_id: str, user_id: str | None = None) -> bool:
    with _LOCK, _conn() as c:
        if user_id is None:
            cur = c.execute("DELETE FROM analyses WHERE id=?", (analysis_id,))
        else:
            cur = c.execute("DELETE FROM analyses WHERE id=? AND user_id=?",
                            (analysis_id, user_id))
    return cur.rowcount > 0
