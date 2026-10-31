"""
duplicate_detector.py — Memory-bounded deduplication for event UIDs.

WHY NOT a plain set?
  37 million events × ~64 bytes per SHA256 hex string ≈ 2.4 GB — blows the 8 GB RAM budget.

HOW IT WORKS:
  We use an OrderedDict as a bounded LRU cache.
  - maxsize=500_000 entries ≈ ~32 MB (64 bytes × 500k)
  - True duplicates only occur when the same chunk is re-processed (crash recovery).
  - In normal runs, byte offsets are unique so event_uids are unique.
  - If the LRU fills up, the oldest entry is evicted — this trades a tiny false-negative
    risk (very old UID re-admitted) for guaranteed memory safety.

  Since event_uid is deterministic from (source_file_id, byte_offset), the only real
  duplicates happen on chunk re-runs — and those are caught within a single ingestion run
  because the chunk windows don't overlap (ChunkReader ensures this).
"""

from collections import OrderedDict
from threading import Lock


class DuplicateDetector:
    """
    Thread-safe, memory-bounded duplicate UID detector.

    Args:
        maxsize: Maximum number of UIDs to keep in memory. Default 500,000.
    """

    def __init__(self, maxsize: int = 500_000):
        self._maxsize = maxsize
        self._seen: OrderedDict = OrderedDict()
        self._lock = Lock()
        self.duplicate_count = 0

    def is_duplicate(self, event_uid: str) -> bool:
        """
        Returns True if this UID was seen before (duplicate).
        If new, records it and returns False.
        Evicts the oldest entry when capacity is exceeded.
        """
        with self._lock:
            if event_uid in self._seen:
                self._seen.move_to_end(event_uid)  # refresh LRU position
                self.duplicate_count += 1
                return True

            # New UID — add it
            self._seen[event_uid] = None
            # Evict oldest if over capacity
            if len(self._seen) > self._maxsize:
                self._seen.popitem(last=False)

            return False

    def reset(self) -> None:
        """Clear all seen UIDs (use between independent ingestion runs)."""
        with self._lock:
            self._seen.clear()
            self.duplicate_count = 0

    @property
    def size(self) -> int:
        """Current number of UIDs held in memory."""
        return len(self._seen)
