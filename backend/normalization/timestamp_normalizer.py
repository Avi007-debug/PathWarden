"""Normalize various epoch, RFC, and custom date formats to UTC."""
from common.utilities import parse_iso_timestamp

class TimestampNormalizer:
    def to_utc(self, val: str) -> str:
        dt = parse_iso_timestamp(val)
        return dt.isoformat() if dt else "1970-01-01T00:00:00+00:00"
