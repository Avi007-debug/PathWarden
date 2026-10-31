"""
checkpoint_manager.py — Crash-safe resume support for the ingestion pipeline.

PROBLEM: If the ingestion pipeline crashes halfway through a 30 GB file, we don't
want to re-process everything from byte 0. We need to know where we left off.

SOLUTION: A JSON checkpoint file that records, per source file:
  - The last committed byte offset (so ChunkReader can resume from there)
  - Which batch IDs have been committed (so we skip re-writing their Parquet)
  - Which Parquet files were written (so DuckDB can re-register them after restart)

ATOMIC WRITES: We write to a `.tmp` file first, then os.replace() — this guarantees
the checkpoint is never in a half-written, corrupt state even if the process is killed
mid-write. This is the same pattern used in ParquetWriter.
"""

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from threading import Lock
from typing import Dict, List, Optional


class CheckpointManager:
    """
    Manages per-file ingestion checkpoints.

    Args:
        checkpoint_path: Path to the JSON checkpoint file (e.g. backend/data/checkpoint.json)
    """

    def __init__(self, checkpoint_path: str):
        self._path = Path(checkpoint_path)
        self._tmp_path = self._path.with_suffix(".tmp")
        self._lock = Lock()
        # Internal state: { source_file_id -> { ... } }
        self._state: Dict[str, dict] = {}
        self._load()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def commit_batch(
        self,
        source_file_id: str,
        batch_id: str,
        end_byte: int,
        parquet_path: str,
    ) -> None:
        """
        Record that a batch has been successfully written.

        Args:
            source_file_id: Identifier for the raw log file.
            batch_id:        Unique batch identifier (from generate_batch_id).
            end_byte:        The byte offset at the END of this chunk (resume point).
            parquet_path:    Absolute path of the Parquet file written for this batch.
        """
        with self._lock:
            entry = self._get_or_create(source_file_id)
            entry["committed_byte_offset"] = max(
                entry["committed_byte_offset"], end_byte
            )
            if batch_id not in entry["completed_batches"]:
                entry["completed_batches"].append(batch_id)
            if parquet_path not in entry["parquet_files"]:
                entry["parquet_files"].append(parquet_path)
            entry["updated_at"] = _now_iso()
            self._save()

    def get_resume_offset(self, source_file_id: str) -> int:
        """
        Return the byte offset to start reading from for this file.
        Returns 0 if no checkpoint exists (fresh start).
        """
        with self._lock:
            entry = self._state.get(source_file_id)
            if entry is None:
                return 0
            return entry["committed_byte_offset"]

    def is_batch_committed(self, batch_id: str) -> bool:
        """
        Return True if this batch_id was already committed.
        Used to skip re-writing Parquet for re-submitted batches.
        """
        with self._lock:
            for entry in self._state.values():
                if batch_id in entry["completed_batches"]:
                    return True
            return False

    def get_all_parquet_files(self) -> List[str]:
        """
        Return a flat list of all Parquet file paths across all source files.
        Used by DuckDB to re-register the events view after a restart.
        """
        with self._lock:
            paths: List[str] = []
            for entry in self._state.values():
                paths.extend(entry["parquet_files"])
            return paths

    def mark_started(self, source_file_id: str) -> None:
        """Record that ingestion has started for a source file (idempotent)."""
        with self._lock:
            self._get_or_create(source_file_id)
            self._save()

    def get_state(self) -> dict:
        """Return a copy of the full checkpoint state (for diagnostics)."""
        with self._lock:
            return json.loads(json.dumps(self._state))

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _get_or_create(self, source_file_id: str) -> dict:
        """Return the entry for source_file_id, creating it if absent."""
        if source_file_id not in self._state:
            self._state[source_file_id] = {
                "committed_byte_offset": 0,
                "completed_batches": [],
                "parquet_files": [],
                "started_at": _now_iso(),
                "updated_at": _now_iso(),
            }
        return self._state[source_file_id]

    def _load(self) -> None:
        """Load existing checkpoint from disk, or start fresh if none."""
        if self._path.exists():
            try:
                with open(self._path, "r", encoding="utf-8") as f:
                    self._state = json.load(f)
            except (json.JSONDecodeError, OSError):
                # Corrupt checkpoint — start fresh (the .tmp file may be valid,
                # but recovery from corruption is safer than using bad state)
                self._state = {}
        else:
            self._state = {}

    def _save(self) -> None:
        """Atomically write checkpoint state to disk."""
        self._path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self._tmp_path
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(self._state, f, indent=2)
        os.replace(tmp, self._path)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()
