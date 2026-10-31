"""Heuristic format detector for log files."""
import json
import csv

def detect_format(filepath: str) -> str:
    ext = filepath.split(".")[-1].lower()
    if ext in ["json", "ndjson", "jsonl"]:
        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                first_line = f.readline().strip()
                if first_line.startswith("{") and first_line.endswith("}"):
                    return "jsonl" if ext in ["ndjson", "jsonl"] else "json"
        except Exception:
            pass
    elif ext in ["csv", "tsv"]:
        return "csv"
    return "text"
