"""Atomic, Zstandard-compressed Parquet batch writer.

Why atomic writes:
    pq.write_table() writes incrementally. If Python or the OS crashes mid-write,
    the target .parquet file is left in a corrupt state. DuckDB will then fail
    on ANY query against the events view because it tries to read all files.

    Solution: write to a .tmp file first, then os.rename() to the final name.
    os.rename() is atomic on Linux, macOS and Windows (same volume). Either
    the rename completes and we have a valid .parquet, or it never happens and
    the .tmp file is cleaned up on the next startup.

Why Zstandard compression:
    Log data has high repetition (same IPs, hostnames, event types appear millions
    of times). Zstd at level 3 gives ~3-4x compression vs uncompressed Parquet
    with negligible CPU cost. DuckDB decompresses column slices lazily during
    queries, so compression never hurts analytical query speed.

Output directory structure:
    data/normalized/
        events_batch_SRC-eaedded0-00000.parquet
        events_batch_SRC-eaedded0-00001.parquet
        ...
    DuckDB queries all of them with: read_parquet('data/normalized/*.parquet')
"""

import os
import glob
import json
from typing import List, Dict, Any, Optional

import pyarrow as pa
import pyarrow.parquet as pq


class ParquetWriter:
    """Writes batches of canonical event records to Parquet files atomically.

    Each call to write_batch() produces one .parquet file. The files are later
    registered as a unified DuckDB view by DuckDBManager.

    Args:
        output_dir   : Directory for Parquet output files. Created if absent.
        compression  : Parquet compression codec. 'zstd' recommended.
        zstd_level   : Zstandard compression level (1=fast, 22=best). 3 is a
                       good balance of speed and compression ratio.
    """

    def __init__(
        self,
        output_dir  : str = "backend/data/normalized",
        compression : str = "zstd",
        zstd_level  : int = 3,
    ):
        self.output_dir   = os.path.abspath(output_dir)
        self.compression  = compression
        self.zstd_level   = zstd_level

        # Create output directory and clean any leftover .tmp files from previous runs
        os.makedirs(self.output_dir, exist_ok=True)
        self._clean_stale_tmp_files()

    # ── Public API ─────────────────────────────────────────────────────────────

    def write_batch(
        self,
        records : List[Dict[str, Any]],
        batch_id: str,
    ) -> str:
        """Write one batch of canonical event records to an atomic Parquet file.

        Args:
            records : List of canonical event dicts (from EventNormalizer).
            batch_id: Unique batch string from identifiers.generate_batch_id().

        Returns:
            Absolute path of the written .parquet file.

        Raises:
            IOError if disk write fails or directory is not writable.
        """
        if not records:
            return ""

        # Pre-process: serialize complex fields to JSON strings
        clean_records = self._serialize_complex_fields(records)

        # PyArrow handles schema inference across homogeneous record dicts
        table = pa.Table.from_pylist(clean_records)

        filename_stem = f"events_batch_{batch_id}"
        tmp_path   = os.path.join(self.output_dir, f"{filename_stem}.tmp")
        final_path = os.path.join(self.output_dir, f"{filename_stem}.parquet")

        # ── Write to .tmp, then atomically rename ─────────────────────────────
        try:
            pq.write_table(
                table,
                tmp_path,
                compression        = self.compression,
                compression_level  = self.zstd_level,
                # Row group size: 128k rows = good balance for DuckDB predicate pushdown
                row_group_size     = 128_000,
            )
            os.replace(tmp_path, final_path)   # atomic on all major platforms
        except Exception:
            # Clean up the incomplete .tmp file if something went wrong
            if os.path.exists(tmp_path):
                os.remove(tmp_path)
            raise

        return final_path

    def write_detections_batch(
        self,
        detections: List[Dict[str, Any]],
        batch_id: str = "001",
    ) -> str:
        """Write a batch of detection records to Parquet atomically."""
        if not detections:
            return ""

        det_records = []
        for d in detections:
            rec = dict(d)
            if isinstance(rec.get("event_uids"), (list, tuple)):
                rec["event_uids"] = json.dumps(rec["event_uids"])
            if isinstance(rec.get("evidence"), (dict, list)):
                rec["evidence"] = json.dumps(rec["evidence"])
            det_records.append(rec)

        table = pa.Table.from_pylist(det_records)
        filename_stem = f"detections_{batch_id}"
        tmp_path = os.path.join(self.output_dir, f"{filename_stem}.tmp")
        final_path = os.path.join(self.output_dir, f"{filename_stem}.parquet")

        try:
            pq.write_table(
                table,
                tmp_path,
                compression=self.compression,
                compression_level=self.zstd_level,
            )
            os.replace(tmp_path, final_path)
        except Exception:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)
            raise

        return final_path

    def list_written_files(self) -> List[str]:
        """Return sorted list of all .parquet files in the output directory."""
        pattern = os.path.join(self.output_dir, "events_batch_*.parquet")
        return sorted(glob.glob(pattern))

    def get_glob_pattern(self) -> str:
        """Return the glob pattern DuckDB uses to query all batches at once."""
        return os.path.join(self.output_dir, "events_batch_*.parquet")

    # ── Private helpers ────────────────────────────────────────────────────────

    def _serialize_complex_fields(
        self,
        records: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        """Serialize lists and dicts to JSON strings for Parquet compatibility."""
        clean = []
        for r in records:
            item = dict(r)
            # dq_flags is stored as a JSON string: '["FLAG1", "FLAG2"]'
            if isinstance(item.get("dq_flags"), (list, set)):
                item["dq_flags"] = json.dumps(sorted(list(item["dq_flags"])))
            # extra is stored as a JSON string: '{"raw_action": "deny"}'
            if isinstance(item.get("extra"), dict):
                item["extra"] = json.dumps(item["extra"])
            clean.append(item)
        return clean

    def _clean_stale_tmp_files(self) -> None:
        """Remove any .tmp files left over from an ungraceful shutdown."""
        tmp_pattern = os.path.join(self.output_dir, "*.tmp")
        for tmp_file in glob.glob(tmp_pattern):
            try:
                os.remove(tmp_file)
            except OSError:
                pass  # Ignore files that cannot be removed (e.g. locked by another process)
