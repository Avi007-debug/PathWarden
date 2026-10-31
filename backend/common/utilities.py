"""Utility helper functions for PathWarden."""

import datetime
from typing import Optional

def parse_iso_timestamp(ts_str: str) -> Optional[datetime.datetime]:
    """Parse various timestamp representations into timezone-aware UTC datetime."""
    try:
        if ts_str.endswith("Z"):
            ts_str = ts_str[:-1] + "+00:00"
        return datetime.datetime.fromisoformat(ts_str).astimezone(datetime.timezone.utc)
    except Exception:
        return None

def format_bytes(bytes_count: int) -> str:
    """Format bytes count into human readable format."""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if bytes_count < 1024.0:
            return f"{bytes_count:.2f} {unit}"
        bytes_count /= 1024.0
    return f"{bytes_count:.2f} PB"

