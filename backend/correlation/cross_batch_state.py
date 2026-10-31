"""PathWarden FR-4: Cross-batch correlation state manager.

Maintains a bounded in-memory sliding window (600s) for open sessions and
process trees that span Parquet batch boundaries.  State is persisted to JSON
after each batch commit so the worker can resume without re-scanning old batches.

Design constraints:
  - Never grows larger than max_gap_seconds worth of entries
  - Prunes expired entries on every write
  - Thread-safe (uses threading.Lock for dict mutations)
  - JSON-serializable state for checkpoint persistence
"""

from __future__ import annotations

import json
import os
import threading
import time
from dataclasses import dataclass, asdict
from typing import Dict, List, Optional, Tuple

from common.logger import get_logger

logger = get_logger("CrossBatchState")

_DEFAULT_WINDOW_SECONDS = 600
_DEFAULT_STATE_PATH = "./data/correlation_state.json"


@dataclass
class OpenSession:
    session_id: str
    host_name: str
    user_name: str
    detection_id: str
    event_ts: float         # epoch seconds
    expires_at: float       # epoch seconds


@dataclass
class OpenProcess:
    process_id: int
    host_name: str
    detection_id: str
    event_ts: float
    expires_at: float
    parent_detection_id: Optional[str] = None


class CrossBatchState:
    """Thread-safe sliding-window state for cross-batch correlation continuity."""

    def __init__(
        self,
        window_seconds: int = _DEFAULT_WINDOW_SECONDS,
        state_path: str = _DEFAULT_STATE_PATH,
    ) -> None:
        self.window_seconds = window_seconds
        self.state_path = state_path
        self._lock = threading.Lock()
        # session_id → OpenSession
        self._sessions: Dict[str, OpenSession] = {}
        # (host, pid) → OpenProcess
        self._processes: Dict[Tuple[str, int], OpenProcess] = {}

    # ------------------------------------------------------------------
    # Session tracking
    # ------------------------------------------------------------------

    def register_session(
        self,
        session_id: str,
        host_name: str,
        user_name: str,
        detection_id: str,
        event_ts: float,
    ) -> None:
        if not session_id:
            return
        with self._lock:
            self._prune_expired(event_ts)
            self._sessions[session_id] = OpenSession(
                session_id=session_id,
                host_name=host_name,
                user_name=user_name,
                detection_id=detection_id,
                event_ts=event_ts,
                expires_at=event_ts + self.window_seconds,
            )

    def lookup_session(self, session_id: str, at_ts: float) -> Optional[OpenSession]:
        """Return open session if still within window, else None."""
        with self._lock:
            sess = self._sessions.get(session_id)
            if sess and sess.expires_at >= at_ts:
                return sess
            return None

    # ------------------------------------------------------------------
    # Process tree tracking
    # ------------------------------------------------------------------

    def register_process(
        self,
        host_name: str,
        process_id: int,
        detection_id: str,
        event_ts: float,
        parent_detection_id: Optional[str] = None,
    ) -> None:
        if process_id is None:
            return
        key = (host_name, process_id)
        with self._lock:
            self._prune_expired(event_ts)
            self._processes[key] = OpenProcess(
                process_id=process_id,
                host_name=host_name,
                detection_id=detection_id,
                event_ts=event_ts,
                expires_at=event_ts + self.window_seconds,
                parent_detection_id=parent_detection_id,
            )

    def lookup_parent_process(
        self, host_name: str, parent_pid: int, at_ts: float
    ) -> Optional[OpenProcess]:
        """Find an open process record for the given parent PID on this host."""
        key = (host_name, parent_pid)
        with self._lock:
            proc = self._processes.get(key)
            if proc and proc.expires_at >= at_ts:
                return proc
            return None

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def save(self) -> None:
        """Persist current state to JSON (idempotent)."""
        with self._lock:
            data = {
                "saved_at": time.time(),
                "window_seconds": self.window_seconds,
                "sessions": {k: asdict(v) for k, v in self._sessions.items()},
                "processes": {
                    f"{k[0]}:{k[1]}": asdict(v) for k, v in self._processes.items()
                },
            }
        os.makedirs(os.path.dirname(self.state_path) or ".", exist_ok=True)
        tmp = self.state_path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2)
        os.replace(tmp, self.state_path)
        logger.debug("CrossBatchState saved: %d sessions, %d processes", len(data["sessions"]), len(data["processes"]))

    def load(self) -> bool:
        """Load state from JSON. Returns True if successfully loaded."""
        if not os.path.exists(self.state_path):
            return False
        try:
            with open(self.state_path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            with self._lock:
                self._sessions = {}
                for k, v in data.get("sessions", {}).items():
                    self._sessions[k] = OpenSession(**v)
                self._processes = {}
                for k, v in data.get("processes", {}).items():
                    host, pid_str = k.rsplit(":", 1)
                    self._processes[(host, int(pid_str))] = OpenProcess(**v)
            logger.info(
                "CrossBatchState loaded: %d sessions, %d processes",
                len(self._sessions), len(self._processes),
            )
            return True
        except Exception as exc:  # noqa: BLE001
            logger.warning("CrossBatchState load failed: %s", exc)
            return False

    def stats(self) -> dict:
        with self._lock:
            return {
                "open_sessions": len(self._sessions),
                "open_processes": len(self._processes),
            }

    # ------------------------------------------------------------------
    # Pruning
    # ------------------------------------------------------------------

    def _prune_expired(self, now_ts: float) -> None:
        """Remove entries older than window. Must be called under _lock."""
        expired_sessions = [k for k, v in self._sessions.items() if v.expires_at < now_ts]
        for k in expired_sessions:
            del self._sessions[k]

        expired_procs = [k for k, v in self._processes.items() if v.expires_at < now_ts]
        for k in expired_procs:
            del self._processes[k]

