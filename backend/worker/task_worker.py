"""PathWarden FR-7: Background task worker thread.

Runs the full pipeline in a daemon thread so FastAPI stays responsive.
Uses JobRegistry for status tracking and CheckpointManager for idempotent batch commits.

Thread-safe: only one RUNNING job at a time (enforced by JobRegistry.get_active_run()).
"""

from __future__ import annotations

import threading
import time
import traceback
import uuid
from typing import Any, Dict, Optional

from common.logger import get_logger
from .job_registry import JobRegistry
from .checkpoint_manager import CheckpointManager
from .pipeline_coordinator import run_pipeline

logger = get_logger("TaskWorker")


class TaskWorker:
    """Manages background pipeline execution in a daemon thread."""

    def __init__(self, registry: JobRegistry) -> None:
        self._registry = registry
        self._checkpoint_mgr = CheckpointManager(registry)
        self._thread: Optional[threading.Thread] = None
        self._current_run_id: Optional[str] = None
        self._lock = threading.Lock()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def submit(
        self,
        dataset_path: str,
        config: Optional[Dict[str, Any]] = None,
        run_id: Optional[str] = None,
    ) -> str:
        """Submit a new analysis run. Returns run_id. Raises if already running."""
        with self._lock:
            active = self._registry.get_active_run()
            if active:
                raise RuntimeError(f"Analysis job already running: {active}")

            run_id = run_id or f"RUN-{uuid.uuid4().hex[:12].upper()}"
            cfg = config or {}
            self._registry.create_job(run_id, dataset_path, cfg)
            self._registry.update_status(run_id, "RUNNING")

            self._current_run_id = run_id
            self._thread = threading.Thread(
                target=self._run_in_thread,
                args=(run_id, dataset_path, cfg),
                daemon=True,
                name=f"PathWarden-Worker-{run_id}",
            )
            self._thread.start()
            logger.info("TaskWorker: started job %s on dataset %s", run_id, dataset_path)
            return run_id

    def is_running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def current_run_id(self) -> Optional[str]:
        return self._current_run_id

    def get_status(self, run_id: str) -> Optional[dict]:
        return self._registry.get_job(run_id)

    # ------------------------------------------------------------------
    # Thread body
    # ------------------------------------------------------------------

    def _run_in_thread(self, run_id: str, dataset_path: str, config: dict) -> None:
        events_processed = 0
        incidents_found = 0
        try:
            def progress_cb(stage: str, pct: int) -> None:
                logger.info("[%s] %s … %d%%", run_id, stage, pct)

            result = run_pipeline(
                run_id=run_id,
                dataset_path=dataset_path,
                config=config,
                progress_callback=progress_cb,
            )
            events_processed = result.get("events_processed", 0)
            incidents_found = result.get("incidents_found", 0)
            self._registry.update_status(
                run_id,
                "COMPLETED",
                events_processed=events_processed,
                incidents_found=incidents_found,
            )
            logger.info(
                "TaskWorker: job %s COMPLETED — %d events, %d incidents",
                run_id, events_processed, incidents_found,
            )
        except Exception:  # noqa: BLE001
            err = traceback.format_exc()
            logger.error("TaskWorker: job %s FAILED:\n%s", run_id, err)
            self._registry.update_status(
                run_id, "FAILED",
                events_processed=events_processed,
                incidents_found=incidents_found,
                error_message=err[-2000:],  # cap to 2000 chars
            )
        finally:
            with self._lock:
                self._current_run_id = None

