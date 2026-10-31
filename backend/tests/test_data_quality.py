"""Tests for data quality and reconciliation."""

from backend.quality.record_validator import RecordValidator
from backend.quality.duplicate_detector import DuplicateDetector
from backend.quality.reconciliation import ReconciliationEngine
from backend.common.enums import ParseStatus


def test_record_validator():
    v = RecordValidator()
    valid_rec = {
        "event_uid": "uid-1",
        "ingest_ts": "2024-01-01T00:00:00Z",
        "source_type": "firewall",
        "raw_event_reference": "ref-1",
        "parse_status": ParseStatus.PARSED.value,
        "dq_flags": [],
        "schema_version": "1.0",
        "extra": "{}",
    }
    is_ok, reasons = v.validate(valid_rec)
    assert is_ok, reasons

    bad_rec = dict(valid_rec, parse_status=ParseStatus.MALFORMED.value)
    is_ok, _ = v.validate(bad_rec)
    assert not is_ok


def test_duplicate_detector():
    dd = DuplicateDetector(maxsize=10)
    assert not dd.is_duplicate("evt-01")
    assert dd.is_duplicate("evt-01")
    assert not dd.is_duplicate("evt-02")


def test_reconciliation_engine():
    rec = ReconciliationEngine()
    rec.record_batch(eligible=10, malformed=2, duplicate_dropped=1, valid_excluded=1)
    assert rec.verify()
    rep = rec.get_report()
    assert rep["records_read"] == 14
    assert rep["eligible"] == 10
