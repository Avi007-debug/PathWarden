"""Tests for data quality."""
from quality.record_validator import RecordValidator

def test_record_validator():
    v = RecordValidator()
    assert v.is_valid({"event_id": "EVT-1", "timestamp": "2026-10-31"})
    assert not v.is_valid({})
