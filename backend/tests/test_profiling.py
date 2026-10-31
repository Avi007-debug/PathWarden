"""Tests for profiling and format detection."""

from backend.profiling.format_detector import detect_format
from backend.profiling.file_inventory import scan_raw_files


def test_format_detector(tmp_path):
    f_jsonl = tmp_path / "test.jsonl"
    f_jsonl.write_text('{"a": 1}\n{"b": 2}\n')
    fmt = detect_format(str(f_jsonl))
    assert fmt == "jsonl"


def test_file_inventory(tmp_path):
    (tmp_path / "test1.log").write_text("content1")
    (tmp_path / "test2.log").write_text("content22")
    inv = scan_raw_files(str(tmp_path))
    assert len(inv) == 2
    assert inv[0]["size_bytes"] >= inv[1]["size_bytes"]
