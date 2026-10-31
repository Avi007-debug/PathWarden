"""Flags assigned for malformed or missing telemetry attributes."""
class QualityFlags:
    TIMESTAMP_SKEW = "TIMESTAMP_SKEW"
    MISSING_PARENT_PID = "MISSING_PARENT_PID"
    UNPARSED_PAYLOAD = "UNPARSED_PAYLOAD"
    DUPLICATE_DROP = "DUPLICATE_DROP"
