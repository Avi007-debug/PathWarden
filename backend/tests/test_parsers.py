"""Tests for parsers."""
from parsers.formats.json_parser import JSONParser

def test_json_parser():
    p = JSONParser()
    res = p.parse_record('{"key": "val"}')
    assert res == {"key": "val"}
