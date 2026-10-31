"""PathWarden FR-7: SQLite job registry for analysis run lifecycle tracking.

Schema:
  analysis_jobs:
    run_id TEXT PRIMARY KEY
    status TEXT          -- PENDING | RUNNING | COMPLETED | FAILED
    created_at REAL      -- epoch seconds
    updated_at REAL
    dataset_path TEXT
    config_json TEXT
    error_message TEXT
    events_processed INTEGER
    incidents_found INTEGER

  pipeline_checkpoints:
    id INTEGER PRIMARY KEY
    run_id TEXT
    batch_id INTEGER
    byte_offset INTEGER
    committed_at REAL
    UNIQUE(run_id, batch_id)   -- idempotent commit
"""

from __future__ import annotations

import json
import os
import sqlite3
import time
import threading
import contextlib
from typing import Dict, List, Optional, Any

from common.logger import get_logger

logger = get_logger("JobRegistry")

_DEFAULT_DB_PATH = "./data/jobs.sqlite3"
_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS analysis_jobs (
    run_id          TEXT PRIMARY KEY,
    status          TEXT NOT NULL DEFAULT 'PENDING',
    created_at      REAL NOT NULL,
    updated_at      REAL NOT NULL,
    dataset_path    TEXT NOT NULL DEFAULT '',
    config_json     TEXT NOT NULL DEFAULT '{}',
    error_message   TEXT,
    events_processed INTEGER DEFAULT 0,
    incidents_found  INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS pipeline_checkpoints (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id        TEXT NOT NULL,
    batch_id      INTEGER NOT NULL,
    byte_offset   INTEGER NOT NULL DEFAULT 0,
    committed_at  REAL NOT NULL,
    UNIQUE(run_id, batch_id)
);

CREATE INDEX IF NOT EXISTS idx_jobs_status ON analysis_jobs(status);
CREATE INDEX IF NOT EXISTS idx_chk_run_id ON pipeline_checkpoints(run_id, batch_id);
"""


class JobRegistry:
    """Thread-safe SQLite-backed job registry."""

    def __init__(self, db_path: str = _DEFAULT_DB_PATH) -> None:
        self.db_path = db_path
        self._lock = threading.Lock()
        os.makedirs(os.path.dirname(db_path) or ".", exist_ok=True)
        self._init_schema()

    # ------------------------------------------------------------------
    # Job lifecycle
    # ------------------------------------------------------------------

    def create_job(self, run_id: str, dataset_path: str, config: dict) -> None:
        now = time.time()
        with self._conn() as con:
            con.execute(
                """INSERT OR IGNORE INTO analysis_jobs
                   (run_id, status, created_at, updated_at, dataset_path, config_json)
                   VALUES (?, 'PENDING', ?, ?, ?, ?)""",
                (run_id, now, now, dataset_path, json.dumps(config)),
            )

    def update_status(
        self,
        run_id: str,
        status: str,
        events_processed: int = 0,
        incidents_found: int = 0,
        error_message: Optional[str] = None,
    ) -> None:
        now = time.time()
        with self._conn() as con:
            con.execute(
                """UPDATE analysis_jobs
                   SET status=?, updated_at=?, events_processed=?,
                       incidents_found=?, error_message=?
                   WHERE run_id=?""",
                (status, now, events_processed, incidents_found, error_message, run_id),
            )

    def get_job(self, run_id: str) -> Optional[Dict[str, Any]]:
        with self._conn() as con:
            row = con.execute(
                "SELECT * FROM analysis_jobs WHERE run_id=?", (run_id,)
            ).fetchone()
        if not row:
            return None
        return dict(zip(
            ["run_id","status","created_at","updated_at","dataset_path",
             "config_json","error_message","events_processed","incidents_found"],
            row,
        ))

    def list_jobs(self, limit: int = 20) -> List[Dict[str, Any]]:
        with self._conn() as con:
            rows = con.execute(
                "SELECT * FROM analysis_jobs ORDER BY created_at DESC LIMIT ?", (limit,)
            ).fetchall()
        cols = ["run_id","status","created_at","updated_at","dataset_path",
                "config_json","error_message","events_processed","incidents_found"]
        return [dict(zip(cols, r)) for r in rows]

    def get_active_run(self) -> Optional[str]:
        """Return run_id of any currently RUNNING job, or None."""
        with self._conn() as con:
            row = con.execute(
                "SELECT run_id FROM analysis_jobs WHERE status='RUNNING' ORDER BY created_at DESC LIMIT 1"
            ).fetchone()
        return row[0] if row else None

    # ------------------------------------------------------------------
    # Checkpoint management
    # ------------------------------------------------------------------

    def save_checkpoint(self, run_id: str, batch_id: int, byte_offset: int = 0) -> None:
        now = time.time()
        with self._conn() as con:
            con.execute(
                """INSERT OR REPLACE INTO pipeline_checkpoints
                   (run_id, batch_id, byte_offset, committed_at)
                   VALUES (?, ?, ?, ?)""",
                (run_id, batch_id, byte_offset, now),
            )

    def get_last_checkpoint(self, run_id: str) -> Optional[Dict[str, Any]]:
        with self._conn() as con:
            row = con.execute(
                """SELECT batch_id, byte_offset, committed_at
                   FROM pipeline_checkpoints
                   WHERE run_id=?
                   ORDER BY batch_id DESC LIMIT 1""",
                (run_id,),
            ).fetchone()
        if not row:
            return None
        return {"batch_id": row[0], "byte_offset": row[1], "committed_at": row[2]}

    # ------------------------------------------------------------------
    # Private
    # ------------------------------------------------------------------

    def _init_schema(self) -> None:
        with self._conn() as con:
            con.executescript(_SCHEMA_SQL)

    @contextlib.contextmanager
    def _conn(self):
        """Yield a connection with auto-commit and guaranteed close on exit."""
        con = sqlite3.connect(self.db_path, timeout=10, check_same_thread=False)
        con.execute("PRAGMA journal_mode=WAL")
        con.execute("PRAGMA synchronous=NORMAL")
        try:
            with con:
                yield con
        finally:
            con.close()

