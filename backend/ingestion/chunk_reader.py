"""Streaming chunk reader for large JSON, CSV, and text files."""
import json
from typing import Generator, List, Dict, Any

def read_jsonl_chunks(filepath: str, chunk_size: int = 5000) -> Generator[List[Dict[str, Any]], None, None]:
    chunk = []
    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                chunk.append(json.loads(line))
            except Exception:
                continue
            if len(chunk) >= chunk_size:
                yield chunk
                chunk = []
    if chunk:
        yield chunk
