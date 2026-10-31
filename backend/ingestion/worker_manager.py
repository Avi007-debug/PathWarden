"""Parallel chunk processing with ProcessPoolExecutor and backpressure.

Why ProcessPoolExecutor over ThreadPoolExecutor:
    Python's GIL (Global Interpreter Lock) prevents true CPU parallelism in
    threads — only one thread runs Python bytecode at a time. Parsing 37 million
    firewall lines or 20 million Windows JSON records is CPU-bound work.

    ProcessPoolExecutor spawns N separate OS processes, each with its own Python
    interpreter and GIL. This gives TRUE parallel execution across CPU cores.

    Trade-off: inter-process communication has more overhead than threads. We
    minimise this by passing only the ChunkDescriptor (small) into workers and
    returning only the normalised records + quality stats back.

Backpressure design:
    Without backpressure, the main process would submit 300 chunks (one per
    64 MB slice of the 20 GB firewall log) before any worker finishes. Those
    300 chunks × 64 MB = 19 GB of raw bytes held in memory waiting. Crash.

    Solution: we cap in-flight futures at (max_workers * 2). Once that many
    futures are pending, the main loop BLOCKS until a worker finishes and frees
    a slot. This keeps at most ~500 MB of raw bytes in flight at any time.

Worker isolation:
    Each worker process calls _process_chunk_worker() — a module-level function
    (not a lambda or nested function). Only module-level functions can be pickled
    and sent to worker processes. The function imports all its dependencies
    locally to avoid sharing any state between processes.
"""

import os
import sys
import time
import dataclasses
from concurrent.futures import ProcessPoolExecutor, Future, as_completed
from typing import Callable, Dict, Generator, List, Optional, Tuple, Any

from common.logger import get_logger
from ingestion.chunk_reader import ChunkDescriptor

logger = get_logger("WorkerManager")


# ── Top-level worker function (must be picklable — no closures, no lambdas) ──

def _process_chunk_worker(
    chunk_dict   : Dict[str, Any],  # ChunkDescriptor as plain dict for pickling
    parsers_dir  : str,              # backend root path to add to sys.path in worker
) -> Dict[str, Any]:
    """Worker entry point: parse and normalise one chunk of raw bytes.

    This function runs in a SEPARATE PROCESS. It has no access to the parent
    process's memory, file handles, or global state. It imports everything it
    needs locally.

    Args:
        chunk_dict : ChunkDescriptor fields as a plain dict (picklable).
        parsers_dir: Path to the backend root so imports work in the subprocess.

    Returns:
        Dict with keys:
          'records'      : List of canonical event dicts (from EventNormalizer).
          'malformed'    : Count of records that could not be parsed.
          'parsed'       : Count of successfully parsed records.
          'chunk_index'  : Echo of input chunk_index (for ordering/logging).
          'batch_id'     : Generated batch identifier.
          'error'        : Error message string if the whole chunk failed, else None.
    """
    # Ensure the backend package is importable inside the worker process
    if parsers_dir not in sys.path:
        sys.path.insert(0, parsers_dir)

    # Import here — inside the worker process — not at module level
    from ingestion.chunk_reader     import ChunkDescriptor
    from normalization.event_normalizer import EventNormalizer
    from common.identifiers         import generate_batch_id
    from common.enums               import ParseStatus

    # Reconstruct ChunkDescriptor from plain dict
    chunk = ChunkDescriptor(**chunk_dict)

    batch_id     = generate_batch_id(chunk.source_file_id, chunk.chunk_index)
    normalizer   = EventNormalizer()
    records: List[Dict] = []
    malformed    = 0
    parsed_count = 0

    try:
        # Decode the raw bytes from the chunk
        # We use 'replace' to handle any stray non-UTF-8 bytes in logs
        raw_text = chunk.raw_bytes.decode("utf-8", errors="replace")
        lines    = raw_text.splitlines()

        # Determine which parser to use based on source_type
        if chunk.source_type == "windows":
            from parsers.formats.jsonl_parser import JSONLParser
            from parsers.adapters.endpoint_adapter import EndpointAdapter
            parser  = JSONLParser()
            adapter = EndpointAdapter()
        else:
            # Default to firewall text parser for 'firewall' source_type
            from parsers.formats.text_parser  import TextParser
            from parsers.adapters.network_adapter import NetworkAdapter
            parser  = TextParser()
            adapter = NetworkAdapter()

        # Track byte offset within this chunk for deterministic event_uid
        current_byte_offset = chunk.start_byte
        current_line_number = chunk.start_line

        for line in lines:
            line_bytes = line.encode("utf-8") + b"\n"

            if not line.strip():
                current_byte_offset += len(line_bytes)
                current_line_number += 1
                continue

            try:
                # Step 1: parse the raw line into a structured dict
                parsed = parser.parse_record(line)

                # Step 2: adapt vendor-specific fields to canonical names
                adapted = adapter.adapt(parsed)

                # Step 3: normalise to the canonical schema
                canonical = normalizer.normalize(
                    adapter_record = adapted,
                    source_file_id = chunk.source_file_id,
                    source_type    = chunk.source_type,
                    byte_offset    = current_byte_offset,
                    line_number    = current_line_number,
                    chunk_index    = chunk.chunk_index,
                )
                records.append(canonical)
                parsed_count += 1

            except Exception:
                # Record is malformed — count it, don't crash the whole chunk
                malformed += 1

            current_byte_offset += len(line_bytes)
            current_line_number += 1

    except Exception as exc:
        # Whole-chunk failure (e.g. decoding error) — return error signal
        return {
            "records"    : [],
            "malformed"  : 0,
            "parsed"     : 0,
            "chunk_index": chunk.chunk_index,
            "batch_id"   : batch_id,
            "error"      : str(exc),
        }

    return {
        "records"    : records,
        "malformed"  : malformed,
        "parsed"     : parsed_count,
        "chunk_index": chunk.chunk_index,
        "batch_id"   : batch_id,
        "error"      : None,
    }


# ── WorkerManager orchestrator (runs in the main process) ────────────────────

class WorkerManager:
    """Orchestrates parallel chunk processing with bounded in-flight futures.

    How it works:
        1. The caller feeds ChunkDescriptors from iter_chunks() into run().
        2. WorkerManager submits each chunk to the ProcessPoolExecutor.
        3. When the in-flight future count hits the cap, it BLOCKS (backpressure)
           until a worker finishes and the caller can write its Parquet batch.
        4. Results are yielded in completion order (not submission order).
           That is fine — each canonical event has a stable event_uid regardless
           of the order its batch is written.

    Args:
        max_workers      : Number of parallel worker processes. Default: 3.
                           Set to os.cpu_count() - 1 for maximum throughput.
        max_in_flight    : Maximum number of futures waiting for results.
                           = max_workers * 2 by default. Higher = more RAM used,
                           lower = workers may idle waiting for the main process.
        backend_root     : Absolute path to the backend/ directory so worker
                           processes can import PathWarden modules.
    """

    def __init__(
        self,
        max_workers  : int = 3,
        max_in_flight: Optional[int] = None,
        backend_root : Optional[str] = None,
    ):
        self.max_workers   = max_workers
        self.max_in_flight = max_in_flight or (max_workers * 2)
        self.backend_root  = backend_root or os.path.abspath(
            os.path.join(os.path.dirname(__file__), "..")
        )
        self._executor: Optional[ProcessPoolExecutor] = None

    def run(
        self,
        chunk_generator: Generator[ChunkDescriptor, None, None],
    ) -> Generator[Dict[str, Any], None, None]:
        """Process all chunks from the generator using the parallel worker pool.

        Yields worker results as they complete. Results may arrive out of
        submission order — that is expected and correct.

        Args:
            chunk_generator: Output of ingestion.chunk_reader.iter_chunks().

        Yields:
            Worker result dicts (keys: records, malformed, parsed, batch_id, error).
        """
        backend_root  = self.backend_root
        in_flight: Dict[Future, int] = {}   # future → chunk_index

        with ProcessPoolExecutor(max_workers=self.max_workers) as executor:
            self._executor = executor

            for chunk in chunk_generator:
                # Convert ChunkDescriptor to plain dict for pickling across processes
                chunk_dict = dataclasses.asdict(chunk)

                # Submit the chunk to the worker pool
                future = executor.submit(
                    _process_chunk_worker,
                    chunk_dict,
                    backend_root,
                )
                in_flight[future] = chunk.chunk_index
                logger.info(
                    f"Submitted chunk {chunk.chunk_index} "
                    f"({len(chunk.raw_bytes) / 1024 / 1024:.1f} MB) "
                    f"| in-flight: {len(in_flight)}"
                )

                # ── Backpressure: drain completed futures when at capacity ────
                # When we have `max_in_flight` futures pending, stop submitting
                # new chunks until at least one worker completes.
                while len(in_flight) >= self.max_in_flight:
                    # as_completed() returns the FIRST future that finishes.
                    # We yield its result and remove it from the in-flight set.
                    for done_future in as_completed(in_flight, timeout=120):
                        result = self._collect_result(done_future, in_flight)
                        del in_flight[done_future]
                        yield result
                        break   # Re-evaluate the while condition after each drain

            # ── Drain remaining futures after the generator is exhausted ──────
            for done_future in as_completed(in_flight, timeout=120):
                result = self._collect_result(done_future, in_flight)
                yield result

        self._executor = None

    def _collect_result(
        self,
        future    : Future,
        in_flight : Dict[Future, int],
    ) -> Dict[str, Any]:
        """Safely retrieve the result from a completed future.

        If the worker raised an exception (not a handled parse error, but a
        crash), we catch it here and return a structured error result so the
        main pipeline can log it and continue rather than crashing entirely.
        """
        chunk_index = in_flight.get(future, -1)
        try:
            result = future.result()
            if result.get("error"):
                logger.error(
                    f"Chunk {chunk_index} failed in worker: {result['error']}"
                )
            else:
                logger.info(
                    f"Chunk {chunk_index} done: "
                    f"{result['parsed']} parsed, {result['malformed']} malformed"
                )
            return result
        except Exception as exc:
            logger.error(f"Worker process crashed on chunk {chunk_index}: {exc}")
            return {
                "records"    : [],
                "malformed"  : 0,
                "parsed"     : 0,
                "chunk_index": chunk_index,
                "batch_id"   : f"BATCH-CRASHED-{chunk_index:05d}",
                "error"      : str(exc),
            }
