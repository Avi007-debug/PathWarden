"""Tests for profiling module."""
from profiling.format_detector import detect_format

def test_detect_format():
    assert detect_format("sample.json") == "json"
    assert detect_format("sample.csv") == "csv"
    assert detect_format("sample.log") == "text"
