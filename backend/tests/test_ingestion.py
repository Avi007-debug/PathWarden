"""Tests for ingestion module."""
from ingestion.file_discovery import discover_files

def test_discover_files(tmp_path):
    f = tmp_path / "test.json"
    f.write_text("{}")
    res = discover_files(str(tmp_path), [".json"])
    assert len(res) == 1
