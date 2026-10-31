"""Tests for ingestion module."""

from backend.ingestion.chunk_reader import iter_chunks
from backend.ingestion.checkpoint_manager import CheckpointManager


def test_chunk_reader(tmp_path):
    log_file = tmp_path / "sample.log"
    log_file.write_bytes(b"line1\nline2\nline3\n")
    chunks = list(iter_chunks(str(log_file), source_file_id="src-01", source_type="firewall", chunk_size=10))
    assert len(chunks) >= 1
    total_bytes = sum(len(c.raw_bytes) for c in chunks)
    assert total_bytes == len(b"line1\nline2\nline3\n")


def test_checkpoint_manager(tmp_path):
    cp_file = tmp_path / "checkpoint.json"
    cm = CheckpointManager(str(cp_file))
    assert cm.get_resume_offset("f1") == 0
    cm.commit_batch("f1", "b1", 1000, "b1.parquet")
    assert cm.get_resume_offset("f1") == 1000
    assert cm.is_batch_committed("b1")
    assert not cm.is_batch_committed("b2")
