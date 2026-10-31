"""Tests for normalization."""
from normalization.normalizer import Normalizer

def test_normalizer():
    n = Normalizer()
    rec = n.normalize_record({"@timestamp": "2026-10-31T08:00:00Z"}, "test")
    assert rec["host_name"] == "UNKNOWN_HOST"
