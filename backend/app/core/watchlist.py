"""Per-user IOC watchlist — custom known-bad indicators (IPs, domains, hashes)
matched against every analysis and live window.

Matches are injected into the Summary as authoritative `watchlist_match`
observations *before* the AI runs, so they influence reasoning and scoring and
can't be downgraded (see analyzer.AUTHORITATIVE).
"""
from __future__ import annotations

import sqlite3
import threading
import uuid
from pathlib import Path

from app.config import settings
from app.core.schema import Observation, validate_severity

_LOCK = threading.Lock()
IOC_TYPES = {"ip", "domain", "hash"}


def _conn() -> sqlite3.Connection:
    Path(settings.DB_PATH).parent.mkdir(parents=True, exist_ok=True)
    c = sqlite3.connect(settings.DB_PATH, timeout=30)
    c.row_factory = sqlite3.Row
    return c


def init_db() -> None:
    with _LOCK, _conn() as c:
        c.execute("""CREATE TABLE IF NOT EXISTS watchlist (
            id TEXT PRIMARY KEY, user_id TEXT NOT NULL,
            type TEXT NOT NULL, value TEXT NOT NULL,
            severity TEXT DEFAULT 'high', note TEXT DEFAULT '',
            created_at TEXT DEFAULT (datetime('now')),
            UNIQUE(user_id, type, value))""")


def list_for(user_id: str) -> list[dict]:
    with _LOCK, _conn() as c:
        rows = c.execute("SELECT * FROM watchlist WHERE user_id=? ORDER BY created_at DESC",
                         (user_id,)).fetchall()
    return [dict(r) for r in rows]


def add(user_id: str, type_: str, value: str, severity: str = "high", note: str = "") -> dict:
    type_ = (type_ or "").lower().strip()
    value = (value or "").strip()
    if type_ not in IOC_TYPES:
        raise ValueError("type must be ip, domain, or hash")
    if not value:
        raise ValueError("value is required")
    rec = {"id": uuid.uuid4().hex[:10], "user_id": user_id, "type": type_,
           "value": value, "severity": validate_severity(severity), "note": note or ""}
    with _LOCK, _conn() as c:
        try:
            c.execute("INSERT INTO watchlist (id,user_id,type,value,severity,note) VALUES (?,?,?,?,?,?)",
                      (rec["id"], user_id, type_, value, rec["severity"], rec["note"]))
        except sqlite3.IntegrityError:
            raise ValueError("That indicator is already on your watchlist")
    return rec


def remove(user_id: str, wid: str) -> bool:
    with _LOCK, _conn() as c:
        cur = c.execute("DELETE FROM watchlist WHERE id=? AND user_id=?", (wid, user_id))
        return cur.rowcount > 0


def apply(summary, user_id: str) -> int:
    """Inject watchlist hits into a Summary as observations. Returns hit count."""
    entries = list_for(user_id)
    if not entries:
        return 0
    iocs = summary.iocs
    present: dict[str, str] = {}
    for v in iocs.ips:
        present[v.lower()] = "ip"
    for v in iocs.domains:
        present[v.lower()] = "domain"
    for v in iocs.hashes:
        present[v.lower()] = "hash"
    haystacks = [d.lower() for d in iocs.domains] + [u.lower() for u in iocs.urls]

    hits = 0
    for e in entries:
        val = e["value"].lower()
        if val in present or any(val in h for h in haystacks):
            hits += 1
            note = f" — {e['note']}" if e.get("note") else ""
            summary.observations.insert(0, Observation(
                id=f"wl-{hits:03d}",
                type="watchlist_match",
                description=f"Custom watchlist hit: {e['value']} ({e['type']}){note}",
                severity_hint=validate_severity(e.get("severity", "high")),
                data={"indicator": e["value"], "ioc_type": e["type"], "note": e.get("note", "")},
                mitre_hints=["T1071"],
            ))
    return hits
