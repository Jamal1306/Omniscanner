import aiosqlite
import json
import os
from datetime import datetime

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "scan_history.db")


async def init_db():
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            "CREATE TABLE IF NOT EXISTS scans ("
            "id INTEGER PRIMARY KEY AUTOINCREMENT,"
            "url TEXT NOT NULL,"
            "hostname TEXT NOT NULL,"
            "scanned_at TEXT NOT NULL,"
            "summary TEXT NOT NULL,"
            "findings TEXT NOT NULL,"
            "raw_data TEXT NOT NULL)"
        )
        await db.commit()


async def save_scan(url, hostname, summary, findings, raw_data):
    async with aiosqlite.connect(DB_PATH) as db:
        cur = await db.execute(
            "INSERT INTO scans (url, hostname, scanned_at, summary, findings, raw_data) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (
                url,
                hostname,
                datetime.utcnow().isoformat(),
                json.dumps(summary),
                json.dumps(findings),
                json.dumps(raw_data, default=str),
            ),
        )
        await db.commit()
        return cur.lastrowid


async def get_all_scans():
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cur = await db.execute(
            "SELECT id, url, hostname, scanned_at, summary FROM scans ORDER BY id DESC"
        )
        rows = await cur.fetchall()
        return [
            {
                "id": row["id"],
                "url": row["url"],
                "hostname": row["hostname"],
                "scanned_at": row["scanned_at"],
                "summary": json.loads(row["summary"]),
            }
            for row in rows
        ]


async def get_scan_by_id(scan_id):
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cur = await db.execute(
            "SELECT * FROM scans WHERE id = ?", (scan_id,)
        )
        row = await cur.fetchone()
        if not row:
            return None
        return {
            "id": row["id"],
            "url": row["url"],
            "hostname": row["hostname"],
            "scanned_at": row["scanned_at"],
            "summary": json.loads(row["summary"]),
            "findings": json.loads(row["findings"]),
            "raw_data": json.loads(row["raw_data"]),
        }


async def delete_scan(scan_id):
    async with aiosqlite.connect(DB_PATH) as db:
        cur = await db.execute(
            "DELETE FROM scans WHERE id = ?", (scan_id,)
        )
        await db.commit()
        return cur.rowcount > 0
