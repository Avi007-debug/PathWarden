"""Tests for log parsers and adapters."""

from backend.parsers.parser_registry import ParserRegistry
from backend.parsers.formats.text_parser import TextParser
from backend.parsers.formats.jsonl_parser import JSONLParser
from backend.common.enums import ParseStatus


def test_text_parser():
    tp = TextParser()
    line = "2024-01-01T00:00:00Z fw-01 action=DENY src=192.168.1.1 dst=10.0.0.1 proto=TCP"
    parsed = tp.parse_record(line)
    assert parsed.get("parse_status") == ParseStatus.PARSED.value
    assert parsed.get("action") == "DENY"
    assert parsed.get("src_ip") == "192.168.1.1"


def test_jsonl_parser():
    jp = JSONLParser()
    line = '{"EventID": 4624, "Computer": "DC01", "TargetUserName": "Alice"}'
    parsed = jp.parse_record(line)
    assert parsed.get("parse_status") == ParseStatus.PARSED.value
    assert parsed.get("EventID") == 4624


def test_parser_registry():
    reg = ParserRegistry()
    p, a = reg.get("firewall")
    assert p.__class__.__name__ == "TextParser"
    assert a.__class__.__name__ == "NetworkAdapter"
