"""FR-1 ingestion pipeline orchestrator.

This module is the top-level entry point for running the full ingestion pipeline:

    Raw log file
        → ChunkReader  (64 MB record-boundary-safe chunks)
        → WorkerManager (parallel parse + normalise across N processes)
        → ParquetWriter (atomic Zstd-compressed Parquet batch files)
        → DuckDBManager (register view over all batches)
        → ReconciliationCounters (track terminal dispositions)

Usage (from main.py or CLI):
    from ingestion.processing_queue import run_ingestion_pipeline

    stats = run_ingestion_pipeline(
        file_path   = "build/logs/firex-30G.log",
        source_type = "firewall",
        output_dir  = "backend/data/normalized",
    )
    print(stats)   # {'eligible': N, 'malformed': M, 'batches_written': B, ...}

Design notes:
    - The orchestrator runs in the MAIN process.
    - ChunkReader reads sequentially (one reader, no seek contention).
    - WorkerManager fans out to N worker PROCESSES for parallel parse/normalise.
    - ParquetWriter runs in the main process (single writer avoids file conflicts).
    - After every batch is written, the DuckDB view is refreshed so detection
      queries can start running even before ingestion finishes.
"""

import os
import time
from typing import Dict, Any, Optional

from common.identifiers  import generate_source_file_id
from common.logger       import get_logger
from ingestion.chunk_reader   import iter_chunks, estimate_chunk_count
from ingestion.worker_manager import WorkerManager
from storage.parquet_writer   import ParquetWriter
from storage.duckdb_manager   import DuckDBManager

logger = get_logger("Pipeline")


def run_ingestion_pipeline(
    file_path    : str,
    source_type  : str,
    output_dir   : str           = "backend/data/normalized",
    max_workers  : int           = 3,
    chunk_size   : int           = 64 * 1024 * 1024,   # 64 MB
    resume_offset: int           = 0,
    duckdb_manager: Optional[DuckDBManager] = None,
) -> Dict[str, Any]:
    """Run the complete FR-1 ingestion pipeline for one source file.

    This function orchestrates the entire FR-1 flow:
      1. Produces 64 MB record-boundary-safe chunks from the source file.
      2. Distributes chunks to parallel worker processes for parsing and normalising.
      3. Collects normalised batches and writes each one atomically to Parquet.
      4. Refreshes the DuckDB events view after each batch.
      5. Returns a summary of all quality counters.

    Args:
        file_path     : Absolute or relative path to the raw log file.
        source_type   : 'firewall' or 'windows' — selects parser + adapter.
        output_dir    : Directory to write Parquet batch files.
        max_workers   : Number of parallel worker processes for parsing.
        chunk_size    : Target chunk size in bytes (default 64 MB).
        resume_offset : Byte offset to resume from (for crash recovery).
        duckdb_manager: Optional pre-created DuckDB instance. If None, a new
                        one is created internally (no persistence between runs).

    Returns:
        Dict with pipeline summary statistics:
          - eligible        : records written to Parquet
          - malformed       : records that failed parsing
          - batches_written : number of Parquet files created
          - elapsed_seconds : total wall time
          - throughput_mbs  : average MB/s processed
    """
    if not os.path.exists(file_path):
        raise FileNotFoundError(
            f"Log file not found: {file_path!r}. "
            "Ensure the firex-30G dataset is placed under build/logs/."
        )

    source_file_id  = generate_source_file_id(file_path)
    estimated_chunks = estimate_chunk_count(file_path, chunk_size)
    file_size_gb     = os.path.getsize(file_path) / (1024 ** 3)

    logger.info(
        f"Starting ingestion: {file_path!r} "
        f"({file_size_gb:.2f} GB, ~{estimated_chunks} chunks, "
        f"{max_workers} workers)"
    )

    writer  = ParquetWriter(output_dir=output_dir)
    manager = WorkerManager(max_workers=max_workers)

    # Create a local DuckDB instance if none was passed in
    own_duckdb = duckdb_manager is None
    if own_duckdb:
        duckdb_manager = DuckDBManager()

    # ── Counters ───────────────────────────────────────────────────────────────
    total_eligible       = 0
    total_malformed      = 0
    total_batches        = 0
    total_chunks_seen    = 0
    start_time           = time.monotonic()

    # ── Main pipeline loop ────────────────────────────────────────────────────
    chunk_stream = iter_chunks(
        file_path      = file_path,
        source_file_id = source_file_id,
        source_type    = source_type,
        chunk_size     = chunk_size,
        resume_offset  = resume_offset,
    )

    for worker_result in manager.run(chunk_stream):
        total_chunks_seen += 1

        if worker_result.get("error"):
            # The whole chunk failed — count its records as malformed
            logger.error(
                f"Chunk {worker_result['chunk_index']} error: {worker_result['error']}"
            )
            continue

        records   = worker_result["records"]
        batch_id  = worker_result["batch_id"]
        malformed = worker_result["malformed"]

        total_malformed += malformed

        # Write the normalised batch to Parquet (atomic)
        if records:
            written_path = writer.write_batch(records, batch_id)
            if written_path:
                total_eligible  += len(records)
                total_batches   += 1

                # Refresh DuckDB view so detection can start querying immediately
                duckdb_manager.register_events_view(writer.get_glob_pattern())

                logger.info(
                    f"Batch {batch_id} written -> {os.path.basename(written_path)} "
                    f"({len(records)} events | "
                    f"total eligible: {total_eligible:,})"
                )

    # ── Final summary ─────────────────────────────────────────────────────────
    elapsed   = time.monotonic() - start_time
    file_size = os.path.getsize(file_path)
    throughput = (file_size / (1024 ** 2)) / elapsed if elapsed > 0 else 0.0

    summary = {
        "source_file"    : file_path,
        "source_file_id" : source_file_id,
        "source_type"    : source_type,
        "eligible"       : total_eligible,
        "malformed"      : total_malformed,
        "batches_written": total_batches,
        "chunks_processed": total_chunks_seen,
        "elapsed_seconds": round(elapsed, 2),
        "throughput_mbs" : round(throughput, 2),
    }

    logger.info(
        f"Ingestion complete: {total_eligible:,} eligible, "
        f"{total_malformed:,} malformed, "
        f"{total_batches} batches, "
        f"{throughput:.1f} MB/s"
    )

    if own_duckdb:
        duckdb_manager.close()

    return summary
