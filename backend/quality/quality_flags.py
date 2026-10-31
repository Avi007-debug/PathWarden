"""
quality_flags.py — Utility functions for managing DQ (data quality) flags on a canonical record.

DQ flags are stored in record["dq_flags"] as a JSON string (a serialized list of strings).
These helpers let the rest of the code add/check flags without caring about the JSON encoding.

Note: The ParquetWriter serializes dq_flags to JSON string for Parquet storage.
      During in-memory processing the record keeps dq_flags as a Python list.
      These helpers work on the in-memory list form.
"""

from typing import List
from backend.common.enums import DQFlag


def add_flag(record: dict, flag: DQFlag) -> None:
    """
    Append flag to record["dq_flags"] (list form) if not already present.
    Creates the list if missing.
    """
    flags = record.get("dq_flags")
    if flags is None:
        record["dq_flags"] = []
        flags = record["dq_flags"]
    # flags may already be a list (in-memory) or a JSON string (after deserialization)
    if isinstance(flags, str):
        import json
        flags = json.loads(flags)
        record["dq_flags"] = flags
    flag_val = flag.value if isinstance(flag, DQFlag) else flag
    if flag_val not in flags:
        flags.append(flag_val)


def has_flag(record: dict, flag: DQFlag) -> bool:
    """Return True if the flag is present on the record."""
    flags = record.get("dq_flags", [])
    if isinstance(flags, str):
        import json
        flags = json.loads(flags)
    flag_val = flag.value if isinstance(flag, DQFlag) else flag
    return flag_val in flags


def get_flags(record: dict) -> List[str]:
    """Return all DQ flag strings on the record (always a plain list)."""
    flags = record.get("dq_flags", [])
    if isinstance(flags, str):
        import json
        flags = json.loads(flags)
    return list(flags)
