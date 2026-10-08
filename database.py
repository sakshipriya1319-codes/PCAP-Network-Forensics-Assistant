"""
models/database.py

SQLite-backed storage for analysis history.
"""
from __future__ import annotations

import json
import logging
import sqlite3
import time
from typing import Optional, List

from config import DATABASE_PATH

log = logging.getLogger(__name__)


def get_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    """Create tables if they don't exist."""
    with get_connection() as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS analyses (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                filename    TEXT NOT NULL,
                filepath    TEXT NOT NULL,
                file_size   INTEGER,
                upload_time REAL,
                status      TEXT DEFAULT 'pending',
                error       TEXT,
                result_json TEXT
            );
        """)
    log.info("Database initialised at %s", DATABASE_PATH)


def create_analysis(filename: str, filepath: str, file_size: int) -> int:
    """Insert a new analysis record and return its id."""
    with get_connection() as conn:
        cur = conn.execute(
            "INSERT INTO analyses (filename, filepath, file_size, upload_time, status) "
            "VALUES (?, ?, ?, ?, 'pending')",
            (filename, filepath, file_size, time.time()),
        )
        return cur.lastrowid


def update_analysis_status(analysis_id: int, status: str, error: str = None) -> None:
    with get_connection() as conn:
        conn.execute(
            "UPDATE analyses SET status=?, error=? WHERE id=?",
            (status, error, analysis_id),
        )


def save_analysis_result(analysis_id: int, result: dict) -> None:
    with get_connection() as conn:
        conn.execute(
            "UPDATE analyses SET result_json=?, status='complete' WHERE id=?",
            (json.dumps(result, default=str), analysis_id),
        )


def get_analysis(analysis_id: int) -> Optional[dict]:
    with get_connection() as conn:
        row = conn.execute(
            "SELECT * FROM analyses WHERE id=?", (analysis_id,)
        ).fetchone()
        if row is None:
            return None
        d = dict(row)
        if d.get("result_json"):
            d["result"] = json.loads(d["result_json"])
        return d


def get_all_analyses() -> List[dict]:
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT id, filename, file_size, upload_time, status FROM analyses "
            "ORDER BY upload_time DESC LIMIT 50"
        ).fetchall()
        return [dict(r) for r in rows]


def delete_analysis(analysis_id: int) -> None:
    with get_connection() as conn:
        conn.execute("DELETE FROM analyses WHERE id=?", (analysis_id,))
