"""Live HTTP verification of all PathWarden API endpoints."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, ".")

from fastapi.testclient import TestClient
import main

client = TestClient(main.app)
all_passed = True

endpoints_to_test = [
    # Status
    ("/status", 200, lambda d: "run_id" in d and "status" in d),
    ("/api/status", 200, lambda d: "memory_budget_gb" in d and "storage_engine" in d),

    # Incidents List
    ("/incidents", 200, lambda d: isinstance(d, list) and len(d) >= 4 and "incident_id" in d[0]),
    ("/api/incidents", 200, lambda d: isinstance(d, list) and "title" in d[0]),

    # Incident Detail (with steps and edges)
    ("/incidents/INC-2026-0841", 200, lambda d: len(d.get("steps", [])) == 8 and len(d.get("edges", [])) == 7),
    ("/api/incidents/INC-2026-0841", 200, lambda d: d["incident_id"] == "INC-2026-0841"),

    # Incident Path / Graph
    ("/incidents/INC-2026-0841/path", 200, lambda d: len(d.get("steps", [])) == 8),
    ("/api/incidents/INC-2026-0841/graph", 200, lambda d: len(d.get("edges", [])) == 7),

    # Reachability
    ("/incidents/INC-2026-0841/reach", 200, lambda d: isinstance(d, list) and len(d) >= 5 and "relationship_type" in d[0]),
    ("/api/incidents/INC-2026-0841/reachability", 200, lambda d: "assets" in d and len(d["assets"]) >= 5),

    # Data Quality
    ("/data-quality", 200, lambda d: d.get("reconciliation_balanced") is True and len(d.get("sources", [])) >= 3),
    ("/api/quality", 200, lambda d: "flags_summary" in d),

    # Benchmarks
    ("/bench", 200, lambda d: "detection_recall_pct" in d.get("metrics", {}) and len(d.get("stages", [])) >= 8),
    ("/api/benchmarks", 200, lambda d: d.get("tier_name") is not None),

    # Evidence
    ("/evidence?event_uid=EVT-WIN-4688-9102&ctx=5", 200, lambda d: d.get("event_uid") == "EVT-WIN-4688-9102"),
    ("/api/evidence/EVT-WIN-4688-9102", 200, lambda d: "raw_log_snippet" in d),

    # Health
    ("/health", 200, lambda d: d.get("status") == "ok"),
]

print("=== PATHWARDEN LIVE HTTP API VERIFICATION ===")
for path, expected_status, validator in endpoints_to_test:
    try:
        res = client.get(path)
        status_ok = res.status_code == expected_status
        data = res.json()
        val_ok = validator(data)
        if status_ok and val_ok:
            print(f"[PASS] {res.status_code} {path}")
        else:
            print(f"[FAIL] {res.status_code} {path} — validation: {val_ok}")
            all_passed = False
    except Exception as exc:
        print(f"[ERROR] {path} — {exc}")
        all_passed = False

# Test POST /run
try:
    res = client.post("/run", json={"dataset_path": "./data", "tier": "ADVANCED_30GB"})
    if res.status_code in (200, 409):
        print(f"[PASS] {res.status_code} POST /run -> {res.json().get('status')}")
    else:
        print(f"[FAIL] {res.status_code} POST /run -> {res.text}")
        all_passed = False
except Exception as exc:
    print(f"[ERROR] POST /run — {exc}")
    all_passed = False

if all_passed:
    print("\n>>> ALL 18 ENDPOINT CHECKS PASSED PERFECTLY (100% COMPLIANT) <<<")
    sys.exit(0)
else:
    print("\n>>> SOME CHECKS FAILED <<<")
    sys.exit(1)
    sys.exit(1)

