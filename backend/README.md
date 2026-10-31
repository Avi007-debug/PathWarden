# PathWarden Backend Subsystem

> **Trace the attack. Expose the path. Defend what matters.**

PathWarden's backend is an evidence-driven cyberattack reconstruction, threat investigation, and lateral reachability assessment engine.

## Architecture

- **Ingestion & Profiling**: Chunked streaming reader with memory-budget gating (strictly <= 8.0 GB RAM constraint).
- **Format Parsers & Adapters**: Modular parser engine supporting JSON, CSV, JSONL, and syslog text logs with ECS schema normalization.
- **Data Quality & Reconciliation**: Dual-pass validation tracking missing fields, temporal skew, duplicate events, and schema drift.
- **Storage Subsystem**: Apache Parquet column-oriented storage queried via in-process embedded DuckDB.
- **Attack Path Reconstruction**: MITRE ATT&CK technique mapping correlated with Lockheed Martin Cyber Kill Chain phases.
- **FastAPI Core**: RESTful API service exposing incident summaries, DAG graph representations, reachability matrices, and quality telemetry.

## Quick Start

```bash
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
pip install -r requirements.txt
python main.py
```

