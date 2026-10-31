"""Identify source taxonomy (EDR, Firewall, Windows Event Log)."""
from typing import Dict, Any

def identify_source_type(sample_record: Dict[str, Any]) -> str:
    keys = set(sample_record.keys())
    if "agent" in keys or "process" in keys:
        return "EDR"
    elif "EventID" in keys or "TimeCreated" in keys:
        return "WINDOWS_EVTX"
    elif "src_ip" in keys and "dest_ip" in keys:
        return "NETWORK"
    return "GENERIC"
