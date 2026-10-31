"""Record-boundary-safe chunked file reader for large log files.

Why this exists:
    The firex-30G dataset is ~20 GB (firewall) + ~10 GB (Windows JSONL).
    Loading even 1 GB into Python memory expands 3-5x into dicts/strings,
    instantly busting the 8 GB RAM budget.

    Solution: read fixed-size byte slices (64 MB each) but always truncate
    at the last newline so records are NEVER split across chunk boundaries.

Design:
    - Binary mode ('rb') for byte-accurate offset tracking and max speed.
    - Each chunk is yielded as a ChunkDescriptor dataclass. Workers receive
      this object, decode and parse it independently.
    - Chunk boundaries are line-safe: a partially read last line is dropped
      from the current chunk and will be re-read at the start of the next,
      because the file pointer stays at the last complete newline.
"""

import os
import dataclasses
from typing import Generator, Optional

# 64 MB per chunk — large enough for throughput, small enough to keep
# 3-4 in-flight chunks well within the 8 GB RAM budget.
DEFAULT_CHUNK_SIZE_BYTES: int = 64 * 1024 * 1024   # 64 MB


@dataclasses.dataclass
class ChunkDescriptor:
    """Everything a worker process needs to parse one chunk independently.

    Attributes:
        file_path     : Absolute path to the source file.
        source_file_id: Stable file ID from identifiers.generate_source_file_id().
        source_type   : 'firewall' or 'windows' — tells the worker which parser to use.
        chunk_index   : Zero-based sequential index of this chunk within the file.
        start_byte    : Byte offset where this chunk starts in the source file (0-based).
        end_byte      : Byte offset of the last byte included in this chunk (exclusive).
        start_line    : Approximate 1-based line number at the start of this chunk.
                        Used for raw_event_reference — may be slightly off near boundaries.
        raw_bytes     : The actual raw bytes of the chunk, decoded UTF-8 by the worker.
    """
    file_path     : str
    source_file_id: str
    source_type   : str
    chunk_index   : int
    start_byte    : int
    end_byte      : int
    start_line    : int
    raw_bytes     : bytes


def iter_chunks(
    file_path    : str,
    source_file_id: str,
    source_type  : str,
    chunk_size   : int = DEFAULT_CHUNK_SIZE_BYTES,
    resume_offset: int = 0,
) -> Generator[ChunkDescriptor, None, None]:
    """Stream a large file as byte-sized, line-boundary-safe chunks.

    This is the entry point for FR-1 ingestion. Each yielded ChunkDescriptor
    is self-contained: a worker process can parse it without touching the
    file handle or any shared state.

    How line-boundary safety works:
        1. We read `chunk_size` bytes from the file.
        2. We search BACKWARD from the end of that block for the last b'\\n'.
        3. We keep only the bytes UP TO AND INCLUDING that newline.
        4. We seek the file pointer BACK to just after that newline,
           so the next read begins at the first byte of the next complete line.
        This guarantees no log line is ever split between two chunks.

    Args:
        file_path     : Path to the raw log file.
        source_file_id: Stable file identifier (from identifiers module).
        source_type   : Adapter type string ('firewall' or 'windows').
        chunk_size    : Target bytes per chunk. Default: 64 MB.
        resume_offset : Byte offset to start reading from. Used by checkpoint
                        manager to skip already-processed bytes on restart.

    Yields:
        ChunkDescriptor for each safe chunk found in the file.
    """
    if not os.path.exists(file_path):
        raise FileNotFoundError(
            f"Source log file not found: {file_path!r}. "
            "Ensure build/logs/ directory is populated."
        )

    chunk_index = 0
    current_line = 1          # tracks approximate 1-based line number

    with open(file_path, "rb") as fh:
        # Jump to the resume point if we are restarting after a crash
        if resume_offset > 0:
            fh.seek(resume_offset)

        while True:
            start_byte = fh.tell()      # physical byte position before read

            raw_block = fh.read(chunk_size)
            if not raw_block:
                break  # end of file — all chunks emitted

            # ── Boundary safety: find the last newline in this block ──────────
            # rfind returns the byte index of the last b'\n' within raw_block.
            # If there is no newline (extremely long single line), we yield the
            # whole block anyway to avoid an infinite loop — a DQFlag will handle it.
            last_newline = raw_block.rfind(b"\n")

            if last_newline == -1 or last_newline == len(raw_block) - 1:
                # Block ends exactly on a newline, or no newline at all — use whole block
                safe_bytes = raw_block
            else:
                # Trim to the last complete line
                safe_bytes = raw_block[: last_newline + 1]
                # Seek back so next read starts at the first byte of the partial line
                fh.seek(start_byte + last_newline + 1)

            end_byte = start_byte + len(safe_bytes)

            yield ChunkDescriptor(
                file_path      = file_path,
                source_file_id = source_file_id,
                source_type    = source_type,
                chunk_index    = chunk_index,
                start_byte     = start_byte,
                end_byte       = end_byte,
                start_line     = current_line,
                raw_bytes      = safe_bytes,
            )

            # Approximate line counter: count newlines in the safe slice
            current_line += safe_bytes.count(b"\n")
            chunk_index  += 1


def estimate_chunk_count(file_path: str, chunk_size: int = DEFAULT_CHUNK_SIZE_BYTES) -> int:
    """Estimate how many chunks a file will produce (for progress display).

    Does not read file contents — uses file size only. The estimate will be
    slightly off because boundary trimming slightly reduces each chunk's size.

    Args:
        file_path : Path to the source file.
        chunk_size: Chunk size in bytes (must match what iter_chunks uses).

    Returns:
        Estimated number of chunks (ceiling division).
    """
    file_size = os.path.getsize(file_path)
    return (file_size + chunk_size - 1) // chunk_size
