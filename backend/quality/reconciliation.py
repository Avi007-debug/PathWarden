"""Exact 4-way terminal disposition reconciliation engine.

Contract invariant (Section 5 of shared interface contract):
    records_read == MALFORMED + DUPLICATE_DROPPED + VALID_EXCLUDED + ELIGIBLE

Every input record must receive EXACTLY ONE terminal disposition. The verify()
method raises if the invariant is broken — this is a hard pipeline error.
"""

import datetime
from typing import Dict, Any, Optional

try:
    from backend.common.enums import TerminalDisposition
except ImportError:
    from common.enums import TerminalDisposition


class ReconciliationEngine:
    """Thread-safe counters for FR-1 terminal disposition tracking.

    One instance per ingestion run. Counters are incremented by the
    processing pipeline as each record is classified. The verify() method
    checks the invariant and get_report() returns the full quality summary.

    NOTE: In the parallel pipeline, worker processes return per-batch counts.
    The main process accumulates them here — no locking needed because only
    the main process calls record_disposition().
    """

    def __init__(self):
        self._counts: Dict[str, int] = {
            TerminalDisposition.MALFORMED.value         : 0,
            TerminalDisposition.DUPLICATE_DROPPED.value : 0,
            TerminalDisposition.VALID_EXCLUDED.value    : 0,
            TerminalDisposition.ELIGIBLE.value          : 0,
        }
        self._records_read    = 0
        self._started_at      = datetime.datetime.utcnow().isoformat() + "Z"
        self._completed_at    : Optional[str] = None

    # ── Recording ──────────────────────────────────────────────────────────────

    def record_disposition(self, disposition: TerminalDisposition, count: int = 1) -> None:
        """Record one or more records receiving a terminal disposition.

        Args:
            disposition: One of the four TerminalDisposition values.
            count      : Number of records (default 1). Use >1 when accumulating
                         batch totals from worker processes.
        """
        self._counts[disposition.value] += count
        self._records_read              += count

    def record_batch(self, eligible: int, malformed: int,
                     duplicate_dropped: int = 0, valid_excluded: int = 0) -> None:
        """Convenience method to record an entire worker batch at once.

        Called by the pipeline orchestrator after each worker result arrives.
        """
        self._counts[TerminalDisposition.ELIGIBLE.value]          += eligible
        self._counts[TerminalDisposition.MALFORMED.value]         += malformed
        self._counts[TerminalDisposition.DUPLICATE_DROPPED.value] += duplicate_dropped
        self._counts[TerminalDisposition.VALID_EXCLUDED.value]    += valid_excluded
        self._records_read += eligible + malformed + duplicate_dropped + valid_excluded

    # ── Invariant verification ─────────────────────────────────────────────────

    def verify(self) -> bool:
        """Check that the 4-way invariant holds.

        Returns True if the invariant holds.
        Raises ValueError with a detailed breakdown if it does not.

        The invariant:
            records_read == MALFORMED + DUPLICATE_DROPPED + VALID_EXCLUDED + ELIGIBLE
        """
        disposition_sum = sum(self._counts.values())

        if disposition_sum != self._records_read:
            raise ValueError(
                f"Reconciliation invariant BROKEN:\n"
                f"  records_read   = {self._records_read}\n"
                f"  disposition sum = {disposition_sum}\n"
                f"  MALFORMED         = {self._counts[TerminalDisposition.MALFORMED.value]}\n"
                f"  DUPLICATE_DROPPED = {self._counts[TerminalDisposition.DUPLICATE_DROPPED.value]}\n"
                f"  VALID_EXCLUDED    = {self._counts[TerminalDisposition.VALID_EXCLUDED.value]}\n"
                f"  ELIGIBLE          = {self._counts[TerminalDisposition.ELIGIBLE.value]}\n"
                f"  DELTA             = {self._records_read - disposition_sum} unaccounted records"
            )
        return True

    # ── Reporting ──────────────────────────────────────────────────────────────

    def finalize(self) -> None:
        """Mark the run as complete (records completed_at timestamp)."""
        self._completed_at = datetime.datetime.utcnow().isoformat() + "Z"

    def get_report(self) -> Dict[str, Any]:
        """Return the full reconciliation report as a serialisable dict.

        This is the FR-1 quality output consumed by the API (/api/quality)
        and by the teammate's FR-4 code for provenance verification.
        """
        eligible = self._counts[TerminalDisposition.ELIGIBLE.value]
        pct_eligible = (eligible / self._records_read * 100) if self._records_read else 0.0

        return {
            "records_read"           : self._records_read,
            "eligible"               : eligible,
            "malformed"              : self._counts[TerminalDisposition.MALFORMED.value],
            "duplicate_dropped"      : self._counts[TerminalDisposition.DUPLICATE_DROPPED.value],
            "valid_excluded"         : self._counts[TerminalDisposition.VALID_EXCLUDED.value],
            "pct_eligible"           : round(pct_eligible, 4),
            "invariant_holds"        : (sum(self._counts.values()) == self._records_read),
            "started_at"             : self._started_at,
            "completed_at"           : self._completed_at,
        }

    def __repr__(self) -> str:
        r = self.get_report()
        return (
            f"ReconciliationEngine("
            f"read={r['records_read']}, eligible={r['eligible']}, "
            f"malformed={r['malformed']}, dup={r['duplicate_dropped']}, "
            f"excluded={r['valid_excluded']})"
        )
