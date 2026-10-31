"""Tests for event normalization."""

from backend.normalization.event_normalizer import EventNormalizer
from backend.common.enums import Outcome


def test_event_normalizer():
    norm = EventNormalizer()
    adapted = {
        "event_ts_original": "2024-01-01T12:00:00Z",
        "action": "DENY",
        "outcome": Outcome.FAILURE.value,
        "src_ip": "192.168.1.100",
        "src_port": 4444,
        "dst_ip": "10.0.0.1",
        "dst_port": 80,
        "network_protocol": "TCP",
    }
    canonical = norm.normalize(
        adapter_record=adapted,
        source_file_id="src-01",
        source_type="firewall",
        byte_offset=1024,
        line_number=42,
        chunk_index=0,
    )
    assert canonical["event_uid"] is not None
    assert canonical["outcome"] == Outcome.FAILURE.value
    assert canonical["src_ip"] == "192.168.1.100"
    assert canonical["schema_version"] == "1.0"
