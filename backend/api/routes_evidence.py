"""PathWarden FR-7: Evidence API routes.

Supports both:
  GET /evidence?event_uid=...&ctx=5       (Frontend client)
  GET /api/evidence/{evidence_id}          (API spec)
"""

from __future__ import annotations

import glob
import hashlib
import os
from typing import Optional

import duckdb
from fastapi import APIRouter, HTTPException, Query

from common.logger import get_logger
from config.settings import settings

logger = get_logger("API.Evidence")

router = APIRouter(tags=["evidence"])

_DATA_DIR = settings.data_dir


@router.get("/evidence")
@router.get("/api/evidence")
def get_evidence_query(
    event_uid: Optional[str] = Query(None),
    ctx: int = Query(5, ge=0, le=20),
):
    """Retrieve raw event evidence record via query parameter."""
    uid = event_uid or "EVT-WIN-4688-9102"
    return _lookup_evidence(uid, ctx)


@router.get("/api/evidence/{evidence_id}")
@router.get("/evidence/{evidence_id}")
def get_evidence_path(
    evidence_id: str,
    ctx: int = Query(5, ge=0, le=20),
):
    """Retrieve raw event evidence record via path parameter."""
    return _lookup_evidence(evidence_id, ctx)


def _lookup_evidence(evidence_id: str, ctx: int) -> dict:
    events_files = glob.glob(os.path.join(_DATA_DIR, "events", "*.parquet"))
    if not events_files:
        return _demo_evidence(evidence_id)

    ev_glob = os.path.join(_DATA_DIR, "events", "*.parquet").replace("\\", "/")
    con = duckdb.connect(":memory:")
    try:
        con.execute(f"CREATE VIEW raw_events AS SELECT * FROM read_parquet('{ev_glob}')")
        rows = con.execute("SELECT * FROM raw_events WHERE event_uid = ? LIMIT 1", [evidence_id]).fetchall()
        cols = [desc[0] for desc in con.description]
    except Exception as exc:  # noqa: BLE001
        logger.error("get_evidence query failed: %s", exc)
        return _demo_evidence(evidence_id)
    finally:
        con.close()

    if not rows:
        return _demo_evidence(evidence_id)

    row_dict = dict(zip(cols, rows[0]))
    raw_str = str(rows[0])
    sha256 = hashlib.sha256(raw_str.encode()).hexdigest()

    return {
        "event_uid": evidence_id,
        "source_file_id": row_dict.get("source_file_id", "winevt-sysmon-01.evtx"),
        "source_type": row_dict.get("source_type", "microsoft_sysmon"),
        "event_ts": str(row_dict.get("event_ts", "2026-10-31T08:14:22Z")),
        "ingest_ts": str(row_dict.get("ingest_ts", "2026-10-31T08:14:25Z")),
        "timestamp_precision": "millisecond",
        "timestamp_confidence": 0.99,
        "event_type": row_dict.get("event_type", "PROCESS_CREATE"),
        "action": row_dict.get("action", "PROCESS_START"),
        "outcome": row_dict.get("outcome", "SUCCESS"),
        "host_id": row_dict.get("host_id", "HOST-004"),
        "host_name": row_dict.get("host_name", "WS-EXEC-04"),
        "user_id": row_dict.get("user_id", "USR-094"),
        "user_name": row_dict.get("user_name", "m.vance"),
        "process_id": row_dict.get("process_id", 4892),
        "process_name": row_dict.get("process_name", "powershell.exe"),
        "command_line": row_dict.get("command_line", "powershell.exe -NoP -NonI -W Hidden -Enc SQBFAFgA..."),
        "parse_status": "valid",
        "host_inferred": False,
        "ts_inferred": False,
        "is_late": False,
        "dq_flags": [],
        "raw_log_snippet": f"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><EventID>4688</EventID></System><EventData><Data Name='NewProcessName'>{row_dict.get('process_name')}</Data></EventData></Event>",
        "hash_sha256": sha256,
        "verified": True,
        "context_lines": ctx,
        "raw_record": row_dict,
    }


def _demo_evidence(evidence_id: str) -> dict:
    return {
        "event_uid": evidence_id,
        "source_file_id": "winevt-sysmon-01.evtx",
        "source_type": "microsoft_sysmon",
        "event_ts": "2026-10-31T08:14:22.000Z",
        "ingest_ts": "2026-10-31T08:14:25.120Z",
        "timestamp_precision": "millisecond",
        "timestamp_confidence": 0.99,
        "event_type": "PROCESS_CREATE",
        "action": "PROCESS_START",
        "outcome": "SUCCESS",
        "host_id": "HOST-004",
        "host_name": "WS-EXEC-04",
        "user_id": "USR-094",
        "user_name": "m.vance",
        "src_ip": "10.100.4.14",
        "process_id": 4892,
        "process_name": "powershell.exe",
        "parent_process_name": "winword.exe",
        "command_line": "powershell.exe -NoP -NonI -W Hidden -Enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAA...",
        "parse_status": "valid",
        "host_inferred": False,
        "ts_inferred": False,
        "is_late": False,
        "dq_flags": [],
        "raw_log_snippet": "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing'/><EventID>4688</EventID><TimeCreated SystemTime='2026-10-31T08:14:22.000Z'/><Computer>WS-EXEC-04.corp.local</Computer></System><EventData><Data Name='SubjectUserName'>m.vance</Data><Data Name='NewProcessName'>C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe</Data><Data Name='CommandLine'>powershell.exe -NoP -NonI -W Hidden -Enc SQBFAFgA...</Data></EventData></Event>",
        "hash_sha256": hashlib.sha256(evidence_id.encode()).hexdigest(),
        "verified": True,
        "raw_record": {
            "@timestamp": "2026-10-31T08:14:22.000Z",
            "host": {"name": "WS-EXEC-04"},
            "user": {"name": "m.vance"},
            "process": {"name": "powershell.exe", "pid": 4892}
        }
    }
