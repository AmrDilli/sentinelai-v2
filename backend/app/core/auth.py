"""Lightweight account system — users + sessions in SQLite, stdlib only.

Passwords are PBKDF2-HMAC-SHA256 with a per-user salt (no plaintext, no external
deps). Sessions are random tokens stored server-side so they survive a restart
and can be revoked on logout. This is appropriately simple for a bootcamp/portfolio
project; for production you'd add HTTPS-only cookies, rate limiting, and rotation.
"""
from __future__ import annotations

import hashlib
import hmac
import secrets
import sqlite3
import threading
import time
from pathlib import Path

from app.config import settings

_LOCK = threading.Lock()
_PBKDF2_ROUNDS = 200_000
SESSION_TTL = 60 * 60 * 24 * 14  # 14 days


def _conn() -> sqlite3.Connection:
    Path(settings.DB_PATH).parent.mkdir(parents=True, exist_ok=True)
    c = sqlite3.connect(settings.DB_PATH, timeout=30)
    c.row_factory = sqlite3.Row
    return c


def init_auth() -> None:
    with _LOCK, _conn() as c:
        c.execute("""CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY, username TEXT UNIQUE NOT NULL,
            salt TEXT NOT NULL, pw_hash TEXT NOT NULL,
            created_at TEXT DEFAULT (datetime('now')))""")
        c.execute("""CREATE TABLE IF NOT EXISTS sessions (
            token TEXT PRIMARY KEY, user_id TEXT NOT NULL,
            created_at REAL NOT NULL)""")


def _hash(password: str, salt: str) -> str:
    return hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt),
                               _PBKDF2_ROUNDS).hex()


def register(username: str, password: str) -> dict:
    username = (username or "").strip().lower()
    if len(username) < 3:
        raise ValueError("Username must be at least 3 characters")
    if len(password or "") < 6:
        raise ValueError("Password must be at least 6 characters")
    salt = secrets.token_hex(16)
    uid = secrets.token_hex(8)
    with _LOCK, _conn() as c:
        if c.execute("SELECT 1 FROM users WHERE username=?", (username,)).fetchone():
            raise ValueError("Username already taken")
        c.execute("INSERT INTO users (id, username, salt, pw_hash) VALUES (?,?,?,?)",
                  (uid, username, salt, _hash(password, salt)))
    return {"id": uid, "username": username}


def login(username: str, password: str) -> dict:
    username = (username or "").strip().lower()
    with _LOCK, _conn() as c:
        row = c.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
        if not row or not hmac.compare_digest(row["pw_hash"], _hash(password, row["salt"])):
            raise ValueError("Invalid username or password")
        token = secrets.token_urlsafe(32)
        c.execute("INSERT INTO sessions (token, user_id, created_at) VALUES (?,?,?)",
                  (token, row["id"], time.time()))
    return {"token": token, "user": {"id": row["id"], "username": row["username"]}}


def logout(token: str) -> None:
    with _LOCK, _conn() as c:
        c.execute("DELETE FROM sessions WHERE token=?", (token,))


def user_for_token(token: str) -> dict | None:
    if not token:
        return None
    with _LOCK, _conn() as c:
        row = c.execute(
            """SELECT u.id, u.username, s.created_at FROM sessions s
               JOIN users u ON u.id = s.user_id WHERE s.token=?""", (token,)).fetchone()
        if not row:
            return None
        if time.time() - row["created_at"] > SESSION_TTL:
            c.execute("DELETE FROM sessions WHERE token=?", (token,))
            return None
    return {"id": row["id"], "username": row["username"]}
