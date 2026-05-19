import hashlib
import secrets
import aiosqlite
import os
from fastapi import HTTPException, Security
from fastapi.security.api_key import APIKeyHeader

DB_PATH = os.path.join(os.path.dirname(__file__), "scan_history.db")

api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


def hash_key(raw: str) -> str:
    return hashlib.sha256(raw.encode()).hexdigest()


async def init_auth(db: aiosqlite.Connection):
    """Create API keys table — called from init_db()."""
    await db.execute("""
        CREATE TABLE IF NOT EXISTS api_keys (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            name       TEXT NOT NULL,
            key_hash   TEXT NOT NULL UNIQUE,
            created_at TEXT NOT NULL,
            last_used  TEXT,
            active     INTEGER DEFAULT 1
        )
    """)
    await db.commit()


async def create_api_key(name: str) -> str:
    """Generate a new API key, store its hash, return the raw key."""
    raw  = "vsk-" + secrets.token_hex(32)
    h    = hash_key(raw)
    from datetime import datetime
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            "INSERT INTO api_keys (name, key_hash, created_at) VALUES (?, ?, ?)",
            (name, h, datetime.utcnow().isoformat()),
        )
        await db.commit()
    return raw


async def verify_api_key(key: str = Security(api_key_header)) -> str:
    """FastAPI dependency — raises 401 if key is missing or invalid."""
    if not key:
        raise HTTPException(status_code=401, detail="X-API-Key header missing")

    h = hash_key(key)
    from datetime import datetime
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cur = await db.execute(
            "SELECT id, name, active FROM api_keys WHERE key_hash = ?", (h,)
        )
        row = await cur.fetchone()
        if not row or not row["active"]:
            raise HTTPException(status_code=401, detail="Invalid or revoked API key")

        # Update last_used timestamp
        await db.execute(
            "UPDATE api_keys SET last_used = ? WHERE key_hash = ?",
            (datetime.utcnow().isoformat(), h),
        )
        await db.commit()
        return row["name"]


async def list_api_keys() -> list:
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cur = await db.execute(
            "SELECT id, name, created_at, last_used, active FROM api_keys ORDER BY id"
        )
        rows = await cur.fetchall()
        return [dict(r) for r in rows]


async def revoke_api_key(key_id: int) -> bool:
    async with aiosqlite.connect(DB_PATH) as db:
        cur = await db.execute(
            "UPDATE api_keys SET active = 0 WHERE id = ?", (key_id,)
        )
        await db.commit()
        return cur.rowcount > 0
