"""File inventory scanner — discovers and classifies raw log files.

Scans a directory tree, detects format and source_type for each file,
and returns a structured inventory without reading file contents fully.
"""

import os
import glob
import datetime
from typing import List, Dict, Any

from profiling.format_detector import detect_format, detect_source_type
from common.identifiers import generate_source_file_id


def scan_raw_files(data_dir: str, extensions: tuple = (".log", ".jsonl", ".json", ".csv", ".txt")) -> List[Dict[str, Any]]:
    """Scan a directory for raw log files and return their inventory metadata.

    Does NOT read file contents beyond the first 8 KB (for format detection).

    Args:
        data_dir  : Root directory to scan recursively.
        extensions: File extensions to include. Others are skipped.

    Returns:
        List of file metadata dicts, sorted by size descending (largest first).
    """
    results = []

    for file_path in glob.glob(os.path.join(data_dir, "**", "*"), recursive=True):
        if not os.path.isfile(file_path):
            continue
        if file_path.endswith(".gitkeep"):
            continue

        _, ext = os.path.splitext(file_path)
        if ext.lower() not in extensions:
            continue

        size_bytes = os.path.getsize(file_path)
        if size_bytes == 0:
            continue

        try:
            fmt         = detect_format(file_path)
            source_type = detect_source_type(file_path)
            file_id     = generate_source_file_id(file_path)
            mtime       = os.path.getmtime(file_path)
        except Exception:
            fmt         = "unknown"
            source_type = None
            file_id     = generate_source_file_id(file_path)
            mtime       = 0.0

        results.append({
            "source_file_id"   : file_id,
            "path"             : os.path.abspath(file_path),
            "name"             : os.path.basename(file_path),
            "size_bytes"       : size_bytes,
            "size_gb"          : round(size_bytes / (1024 ** 3), 3),
            "extension"        : ext.lower(),
            "detected_format"  : fmt,
            "source_type"      : source_type,
            "modified_at"      : datetime.datetime.utcfromtimestamp(mtime).isoformat() + "Z",
        })

    # Largest files first — process the heavy hitters before small ones
    return sorted(results, key=lambda x: x["size_bytes"], reverse=True)


def build_manifest_from_directory(data_dir: str) -> Dict[str, Any]:
    """Build a full ingestion manifest for all raw files in a directory.

    Returns a dict suitable for the checkpoint_manager to track progress.
    """
    files = scan_raw_files(data_dir)
    return {
        "scan_dir"      : os.path.abspath(data_dir),
        "scanned_at"    : datetime.datetime.utcnow().isoformat() + "Z",
        "total_files"   : len(files),
        "total_size_gb" : round(sum(f["size_gb"] for f in files), 3),
        "files"         : files,
    }
