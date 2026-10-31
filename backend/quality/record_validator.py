"""
record_validator.py — Checks if a canonical event record has all required fields.

A record is ELIGIBLE only if:
  - parse_status != MALFORMED
  - All required fields are present and non-null
"""

from typing import List, Tuple
from backend.common.enums import ParseStatus

# Fields that MUST be present and non-null for a record to be eligible
_REQUIRED_FIELDS = [
    "event_uid",
    "ingest_ts",
    "source_type",
    "raw_event_reference",
    "parse_status",
    "dq_flags",
    "schema_version",
    "extra",
]


class RecordValidator:
    """
    Validates a single canonical event dict.

    Usage:
        validator = RecordValidator()
        is_ok, reasons = validator.validate(record)
    """

    def validate(self, record: dict) -> Tuple[bool, List[str]]:
        """
        Returns (is_eligible, reasons).
        is_eligible=False means the record should be counted as MALFORMED.
        reasons lists every problem found.
        """
        reasons: List[str] = []

        # Rule 1: parse_status must not already be MALFORMED
        ps = record.get("parse_status")
        if ps == ParseStatus.MALFORMED.value or ps == ParseStatus.MALFORMED:
            reasons.append("parse_status is MALFORMED")

        # Rule 2: all required fields must be present and non-null
        for field in _REQUIRED_FIELDS:
            if field not in record:
                reasons.append(f"missing required field: {field}")
            elif record[field] is None:
                reasons.append(f"null value for required field: {field}")

        is_eligible = len(reasons) == 0
        return is_eligible, reasons
