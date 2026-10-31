"""High-performance line-delimited JSON (JSONL/NDJSON) parser.

Why this exists:
    The Windows telemetry stream (firex-30G.win.jsonl) contains ~20 million
    JSON objects, one per line. Python's built-in json.loads() works correctly
    but is measurably slow at this scale.

    We use orjson (Rust-backed) when available: 3-10x faster than stdlib json.
    If orjson is not installed, we fall back silently to stdlib json.
    The caller sees no difference — same interface, same output structure.

Malformed line handling:
    Real log files have occasional truncated lines from:
      - Log rotation mid-write (the last line gets cut off)
      - Buffer overflows in the log agent
      - Network transmission errors for remote syslog

    We catch JSONDecodeError per line and return a PARTIAL parse record
    rather than crashing the entire chunk. The reconciliation counters
    then track these as malformed records.
"""

from typing import Any, Dict

from parsers.base_parser import BaseParser
from common.enums import ParseStatus

# Try to import orjson (Rust-backed, 3-10x faster). Fall back to stdlib.
try:
    import orjson as _json_lib
    _JSON_BACKEND = "orjson"

    def _loads(s: str) -> Any:
        # orjson.loads() accepts str or bytes
        return _json_lib.loads(s)

except ImportError:
    import json as _json_lib
    _JSON_BACKEND = "json"

    def _loads(s: str) -> Any:
        return _json_lib.loads(s)


class JSONLParser(BaseParser):
    """Parser for line-delimited JSON records (one JSON object per line).

    Designed for Windows Security Event logs in Winlogbeat/ECS format, but
    handles any valid JSONL stream. Unknown top-level fields pass through
    to the adapter, which routes them into `extra`.

    Attributes:
        backend: String name of the JSON library in use ('orjson' or 'json').
                 Logged at startup for reproducibility.
    """

    backend: str = _JSON_BACKEND

    def parse_record(self, raw_data: Any) -> Dict[str, Any]:
        """Parse one JSONL line into a Python dict.

        Args:
            raw_data: A single text line (str) or raw bytes from the chunk.
                      May contain a trailing newline — we strip it.

        Returns:
            Parsed dict with all JSON fields intact, plus 'parse_status'.
            On decode failure, returns a minimal dict with PARTIAL status
            and the raw line preserved for quarantine.
        """
        if isinstance(raw_data, bytes):
            line = raw_data.decode("utf-8", errors="replace").strip()
        else:
            line = str(raw_data).strip()

        if not line:
            return {"parse_status": ParseStatus.MALFORMED.value}

        try:
            record = _loads(line)

            # Sanity check: JSONL should produce a dict, not a list or scalar
            if not isinstance(record, dict):
                return {
                    "raw_line"    : line,
                    "parse_status": ParseStatus.PARTIAL.value,
                    "parse_error" : f"Expected JSON object, got {type(record).__name__}",
                }

            record["parse_status"] = ParseStatus.PARSED.value
            return record

        except (ValueError, UnicodeDecodeError) as exc:
            # JSONDecodeError is a subclass of ValueError
            return {
                "raw_line"    : line[:500],   # truncate to avoid huge quarantine records
                "parse_status": ParseStatus.MALFORMED.value,
                "parse_error" : str(exc)[:200],
            }
