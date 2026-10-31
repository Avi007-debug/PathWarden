"""PathWarden Performance & Scalability Benchmark Suite.

Benchmarks:
  1. Ingestion & Parallel Chunk Processing Throughput (MB/s, events/sec)
  2. Parsing & Canonical Normalization Speed
  3. Analytical DuckDB Detection Engine Query Latencies
  4. Memory Budget Enforcement (bounded <= 8.0 GB)
"""

import sys
import os
import time
import tempfile
import json
import psutil

# Ensure repo root and backend root are on sys.path
_repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
_backend_root = os.path.join(_repo_root, "backend")
if _repo_root not in sys.path:
    sys.path.insert(0, _repo_root)
if _backend_root not in sys.path:
    sys.path.insert(0, _backend_root)

from backend.ingestion.processing_queue import run_ingestion_pipeline
from backend.storage.duckdb_manager import DuckDBManager
from backend.detection.detection_engine import DetectionEngine
from backend.detection.rule_loader import RuleLoader


def generate_benchmark_log(file_path: str, line_count: int = 50_000) -> int:
    """Generate a synthetic firewall log file for benchmarking."""
    lines = []
    for i in range(line_count):
        ip_tail = (i % 250) + 1
        port = 1000 + (i % 5000)
        action = "DENY" if (i % 5 == 0) else "ALLOW"
        lines.append(
            f"2026-10-31 12:{i%60:02d}:00 src=192.168.1.{ip_tail} spt={port} dst=10.0.0.1 dpt=80 proto=TCP action={action}\n"
        )
    content = "".join(lines).encode("utf-8")
    with open(file_path, "wb") as f:
        f.write(content)
    return len(content)


def run_benchmark():
    print("=" * 65)
    print("  PATHWARDEN INGESTION & DETECTION ENGINE BENCHMARK")
    print("=" * 65)

    proc = psutil.Process()
    mem_before_mb = proc.memory_info().rss / (1024 * 1024)

    with tempfile.TemporaryDirectory() as tmpdir:
        raw_log = os.path.join(tmpdir, "bench_firewall.log")
        out_dir = os.path.join(tmpdir, "normalized")
        os.makedirs(out_dir, exist_ok=True)

        print("\n[1/3] Generating synthetic benchmark corpus (50,000 events)...")
        file_size_bytes = generate_benchmark_log(raw_log, line_count=50_000)
        file_size_mb = file_size_bytes / (1024 * 1024)
        print(f"      Corpus size: {file_size_mb:.2f} MB")

        # Step 1: Ingestion Benchmark
        print("\n[2/3] Benchmarking FR-1 parallel ingestion pipeline...")
        t0 = time.perf_counter()
        summary = run_ingestion_pipeline(
            file_path=raw_log,
            source_type="firewall",
            output_dir=out_dir,
            max_workers=2,
            chunk_size=4 * 1024 * 1024,  # 4 MB chunks for benchmark
        )
        t_ingest = time.perf_counter() - t0
        events_processed = summary.get("records_read", 50000)
        ingest_mbs = file_size_mb / t_ingest if t_ingest > 0 else 0
        eps = events_processed / t_ingest if t_ingest > 0 else 0

        print(f"      Ingestion time      : {t_ingest:.2f}s")
        print(f"      Throughput          : {ingest_mbs:.2f} MB/s")
        print(f"      Event rate          : {eps:,.0f} events/s")
        print(f"      Eligible records    : {summary.get('eligible', 0):,}")
        print(f"      Reconciliation      : Invariant holds = {summary.get('invariant_holds')}")

        # Step 2: Detection Benchmark
        print("\n[3/3] Benchmarking FR-2 / FR-3 DuckDB analytical detection rules...")
        duck = DuckDBManager()
        duck.register_events_view(out_dir)

        rule_loader = RuleLoader()
        rules = rule_loader.load_rules()
        engine = DetectionEngine(duckdb_manager=duck, rule_loader=rule_loader)

        t_det0 = time.perf_counter()
        detections = engine.evaluate_rules(rules)
        t_det = time.perf_counter() - t_det0
        det_lat_ms = (t_det / len(rules) * 1000) if rules else 0

        mem_peak_mb = proc.memory_info().rss / (1024 * 1024)

        print(f"      Total rules run     : {len(rules)}")
        print(f"      Total detections    : {len(detections)}")
        print(f"      Evaluation time     : {t_det:.3f}s")
        print(f"      Avg latency / rule  : {det_lat_ms:.2f} ms")
        print(f"      Peak process memory : {mem_peak_mb:.1f} MB (Budget: 8,192 MB)")

        duck.close()

        # Output results dict
        results = {
            "file_size_mb": round(file_size_mb, 2),
            "events_processed": events_processed,
            "ingestion_seconds": round(t_ingest, 3),
            "throughput_mbs": round(ingest_mbs, 2),
            "events_per_second": round(eps, 1),
            "rule_count": len(rules),
            "detections_count": len(detections),
            "avg_rule_latency_ms": round(det_lat_ms, 2),
            "peak_memory_mb": round(mem_peak_mb, 1),
            "memory_budget_mb": 8192,
            "memory_budget_respected": mem_peak_mb <= 8192,
        }

        bench_out = os.path.join(os.path.dirname(__file__), "benchmark_results.json")
        with open(bench_out, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2)

        print(f"\n[OK] Benchmark results saved to {bench_out}")
        print("=" * 65)


if __name__ == "__main__":
    run_benchmark()
