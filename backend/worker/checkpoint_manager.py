"""PathWarden FR-7: Checkpoint manager — idempotent batch commit/resume.

Wraps JobRegistry.save_checkpoint with idempotency guarantee: committing
the same (run_id, batch_id) twice is a no-op (SQLite UNIQUE constraint).
"""

from __future__ import annotations

from typing import Optional

from .job_registry import JobRegistry
from common.logger import get_logger

logger = get_logger("CheckpointManager")


class CheckpointManager:
    """Idempotent batch-level checkpoint manager backed by JobRegistry."""

    def __init__(self, registry: JobRegistry) -> None:
        self._registry = registry

    def commit_batch(
        self,
        run_id: str,
        batch_id: int,
        byte_offset: int = 0,
    ) -> None:
        """Mark batch_id as processed for run_id. Idempotent — safe to call multiple times."""
        try:
            self._registry.save_checkpoint(run_id, batch_id, byte_offset)
            logger.debug("Checkpoint committed: run=%s batch=%d offset=%d", run_id, batch_id, byte_offset)
        except Exception as exc:  # noqa: BLE001
            logger.error("Checkpoint commit failed: run=%s batch=%d — %s", run_id, batch_id, exc)
            raise

    def get_resume_point(self, run_id: str) -> Optional[dict]:
        """Return {'batch_id': N, 'byte_offset': M} or None if no checkpoint."""
        return self._registry.get_last_checkpoint(run_id)

    def should_skip_batch(self, run_id: str, batch_id: int) -> bool:
        """Return True if this batch was already committed (resume logic)."""
        checkpoint = self.get_resume_point(run_id)
        if checkpoint is None:
            return False
        return batch_id <= checkpoint["batch_id"]

