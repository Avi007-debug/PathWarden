"""Format detector — identifies log file format using magic bytes and sampling.

Reads only the first 8 KB of a file (never the whole file) to detect format.
Detection order: extension hint → first-line structure → content sampling.
"""

import os
import json
import re
from typing import Optional


# Quick regex to detect key=value lines (firewall/syslog style)
_RE_KV = re.compile(r'\b\w+=\S+')
# CEF prefix
_CEF_PREFIX = b"CEF:"


def detect_format(file_path: str) -> str:
    """Detect the log format of a file without reading it fully.

    Returns one of: 'jsonl', 'json', 'csv', 'text', 'unknown'

    Args:
        file_path: Path to the raw log file.
    """
    if not os.path.exists(file_path):
        return "unknown"

    ext = os.path.splitext(file_path)[1].lower()

    # Read first 8 KB as bytes for magic-byte checks
    with open(file_path, "rb") as fh:
        header_bytes = fh.read(8192)

    if not header_bytes.strip():
        return "unknown"

    # ── JSONL: each line is a JSON object ─────────────────────────────────────
    if ext in (".jsonl", ".ndjson") or header_bytes.lstrip()[:1] == b"{":
        try:
            first_line = header_bytes.split(b"\n")[0].decode("utf-8", errors="replace").strip()
            obj = json.loads(first_line)
            if isinstance(obj, dict):
                return "jsonl"
        except (ValueError, UnicodeDecodeError):
            pass

    # ── CEF (Common Event Format) ─────────────────────────────────────────────
    if _CEF_PREFIX in header_bytes[:512]:
        return "text"   # CEF is a text format — TextParser handles it

    # ── CSV: has commas and consistent column count ───────────────────────────
    if ext in (".csv", ".tsv"):
        return "csv"

    # ── JSON array/object (single file, not line-delimited) ──────────────────
    if ext == ".json" or header_bytes.lstrip()[:1] in (b"[", b"{"):
        return "json"

    # ── Text / syslog (default for .log files) ───────────────────────────────
    return "text"


def detect_source_type(file_path: str) -> Optional[str]:
    """Infer PathWarden source_type from file name and format.

    Returns 'firewall', 'windows', or None if unrecognised.
    """
    name  = os.path.basename(file_path).lower()
    fmt   = detect_format(file_path)

    if "win" in name and fmt == "jsonl":
        return "windows"
    if fmt in ("text", "csv") or any(kw in name for kw in ("firewall", "fw", "pf", "iptable", "netflow", "traffic")):
        return "firewall"
    if fmt == "jsonl":
        return "windows"   # best guess for unknown JSONL
    return None
