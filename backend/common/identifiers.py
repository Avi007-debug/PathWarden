"""PathWarden stable identifier generators.

Contract rules (Section 1 & Section 6 of shared interface contract):
  - event_uid must be STABLE: the same raw record must always produce the same
    event_uid across retries, restarts, and parallel workers.
  - Never reuse an event_uid for a different event.
  - Preserve source_event_id separately — never replace it with event_uid.
  - detection_id is unique per detection run (not deterministic — that is fine).
  - batch_id is stable for checkpointing: same file chunk = same batch_id.

Design choice — why (source_file_id + byte_offset) for event_uid:
  If we hash the raw record string, any whitespace difference (trailing space,
  different line endings) produces a different ID for what is logically the
  same event. By anchoring to the physical position in the file, we get:
    1. True stability across retries and parallel workers.
    2. Natural deduplication: same file + same offset = same event.
    3. raw_event_reference is implicitly embedded in the ID itself.
"""

import hashlib
import uuid
from typing import Optional


# ── Canonical event identifier ─────────────────────────────────────────────────

def generate_event_uid(source_file_id: str, byte_offset: int) -> str:
    """Generate a stable, deterministic PathWarden event UID.

    Combines the stable file identifier and the physical byte offset of the
    record's first byte in the source file. Re-processing the same chunk after
    a crash will produce the SAME event_uid — preventing phantom duplicates.

    Format: EVT-<16-char hex digest>
    Example: EVT-3a8f21bc904d1e7c

    Args:
        source_file_id: Stable file identifier (e.g. SHA256 of the file path
                        or a manifest-assigned ID like "firex-30G-firewall").
        byte_offset   : Zero-based byte offset of the record's first byte.

    Returns:
        A 20-character string prefixed with "EVT-".
    """
    raw = f"{source_file_id}::{byte_offset}"
    digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]
    return f"EVT-{digest}"


def generate_event_id() -> str:
    """Legacy helper for backward compatibility."""
    return f"EVT-{uuid.uuid4().hex[:12].upper()}"


# ── Detection identifier ───────────────────────────────────────────────────────

def generate_detection_id() -> str:
    """Generate a unique (non-deterministic) detection record identifier.

    Detections are generated once during the detection pass and are NOT
    re-created on retry (unlike events). uuid4 is appropriate here.

    Format: DET-<8-char uppercase hex>
    Example: DET-4A1F9C2B
    """
    return f"DET-{uuid.uuid4().hex[:8].upper()}"


# ── Incident identifier (FR-4 / FR-5) ─────────────────────────────────────────

def generate_incident_id(index: Optional[int] = None) -> str:
    """Generate an incident identifier for correlated attack paths."""
    if index is not None:
        return f"INC-{index:03d}"
    return f"INC-{uuid.uuid4().hex[:8].upper()}"


# ── Batch / chunk identifier ──────────────────────────────────────────────────

def generate_batch_id(source_file_id: str, chunk_index: int) -> str:
    """Generate a stable batch identifier for checkpoint tracking.

    The same file + chunk index always produces the same batch_id.
    This is used by the checkpoint manager to record which batches have been
    successfully written to Parquet without re-processing them on restart.

    Format: BATCH-<file_id_prefix>-<zero-padded chunk index>
    Example: BATCH-firex-30G-firewall-00042
    """
    file_prefix = source_file_id[:12].replace(" ", "_")
    return f"BATCH-{file_prefix}-{chunk_index:05d}"


# ── Source file identifier ─────────────────────────────────────────────────────

def generate_source_file_id(file_path: str) -> str:
    """Generate a stable, human-readable source file identifier.

    Based on the file path string (not its contents) so it is computed
    instantly without reading the file. If two paths point to the same
    logical file, they produce the same ID — which is correct behavior.

    Format: SRC-<12-char hex>
    Example: SRC-f3a21bc904d1

    Args:
        file_path: Absolute or relative path to the raw log file.
    """
    digest = hashlib.sha256(file_path.encode("utf-8")).hexdigest()[:12]
    return f"SRC-{digest}"


# ── Raw event reference ────────────────────────────────────────────────────────

def build_raw_event_reference(source_file_id: str, byte_offset: int, line_number: int) -> str:
    """Build the raw_event_reference string stored in every canonical event.

    This string allows any downstream consumer (FR-4, analysts, auditors) to
    locate the exact original bytes in the source file without ambiguity.

    Format: <source_file_id>@byte:<byte_offset>:line:<line_number>
    Example: SRC-f3a21bc904d1@byte:4308993064:line:8166076

    Args:
        source_file_id: Stable file identifier.
        byte_offset   : Zero-based byte offset of the record start.
        line_number   : One-based line number (matching the manifest convention).
    """
    return f"{source_file_id}@byte:{byte_offset}:line:{line_number}"
