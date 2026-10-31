"""Validate record completeness and sanity checks."""
class RecordValidator:
    def is_valid(self, record: dict) -> bool:
        return bool(record.get("event_id") and record.get("timestamp"))
