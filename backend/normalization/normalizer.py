"""Normalizer engine applying field mappings and schemas."""
from typing import Dict, Any
from common.identifiers import generate_event_id
from common.utilities import parse_iso_timestamp

class Normalizer:
    def normalize_record(self, raw: Dict[str, Any], source: str) -> Dict[str, Any]:
        ts = parse_iso_timestamp(str(raw.get("@timestamp") or raw.get("timestamp") or "2026-10-31T08:00:00Z"))
        return {
            "event_id": generate_event_id(str(raw)),
            "timestamp": ts.isoformat() if ts else "2026-10-31T08:00:00+00:00",
            "source": source,
            "host_name": str(raw.get("agent", {}).get("hostname") or raw.get("host", {}).get("name") or "UNKNOWN_HOST"),
            "user_name": str(raw.get("user", {}).get("name") or "SYSTEM"),
            "process_name": str(raw.get("process", {}).get("executable") or raw.get("process", {}).get("name") or "unknown.exe"),
            "command_line": str(raw.get("process", {}).get("command_line") or ""),
            "raw": raw
        }
