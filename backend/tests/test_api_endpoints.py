"""Unit and integration test suite for all PathWarden API endpoints."""

import pytest
from api.routes_incidents import list_incidents, get_incident, get_incident_path
from api.routes_reachability import get_incident_reach_items, get_incident_reachability_dict
from api.routes_evidence import get_evidence_query, get_evidence_path
from api.routes_quality import get_data_quality
from api.routes_benchmarks import get_benchmarks
from main import get_system_status, health


def test_api_status_endpoint():
    status = get_system_status()
    assert "memory_budget_gb" in status
    assert "active_incidents" in status
    assert status["engine_mode"] == "DUCKDB_PARQUET_OUT_OF_CORE"


def test_api_health_endpoint():
    h = health()
    assert h.get("status") == "ok"


def test_api_list_incidents():
    incidents = list_incidents(limit=10, offset=0)
    assert isinstance(incidents, list)
    assert len(incidents) >= 4
    first = incidents[0]
    assert "incident_id" in first
    assert "fp_verification" in first
    assert first["fp_verification"]["verdict"] in [
        "CONFIRMED_MALICIOUS_ATTACK",
        "BENIGN_ADMIN_ACTIVITY",
        "SUSPICIOUS_UNVERIFIED",
    ]


def test_api_get_incident_detail():
    inc = get_incident("INC-2026-0841")
    assert inc["incident_id"] == "INC-2026-0841"
    assert len(inc["steps"]) == 8
    assert len(inc["edges"]) == 7
    assert "fp_verification" in inc
    assert inc["fp_verification"]["verdict"] == "CONFIRMED_MALICIOUS_ATTACK"
    assert inc["fp_verification"]["attack_confidence"] >= 0.90
    assert inc["fp_verification"]["false_positive_risk"] <= 0.10

    # Verify network threat on step 1 & 8
    step1 = inc["steps"][0]
    step8 = inc["steps"][7]
    assert step1.get("network_threat") is not None
    assert step8.get("network_threat") is not None
    assert step8["network_threat"]["threat_category"] == "C2_BEACONING"
    assert step8["network_threat"]["destination_ip"] == "198.51.100.44"


def test_api_get_incident_path():
    path = get_incident_path("INC-2026-0841")
    assert path["incident_id"] == "INC-2026-0841"
    assert len(path["steps"]) == 8
    assert len(path["edges"]) == 7


def test_api_reachability_endpoint():
    reach = get_incident_reach_items("INC-2026-0841")
    assert isinstance(reach, list)
    assert len(reach) >= 5
    types = {r["relationship_type"] for r in reach}
    assert "OBSERVED_SESSION" in types or "NETWORK_REACHABLE" in types

    reach_dict = get_incident_reachability_dict("INC-2026-0841")
    assert reach_dict["incident_id"] == "INC-2026-0841"
    assert "assets" in reach_dict


def test_api_evidence_endpoint():
    evi = get_evidence_query(event_uid="EVT-WIN-4688-9102", ctx=5)
    assert evi["event_uid"] == "EVT-WIN-4688-9102"
    assert "raw_log_snippet" in evi
    assert "raw_record" in evi

    evi_path = get_evidence_path(evidence_id="EVT-WIN-4688-9102", ctx=5)
    assert evi_path["event_uid"] == "EVT-WIN-4688-9102"


def test_api_data_quality_endpoint():
    dq = get_data_quality()
    assert dq["reconciliation_balanced"] is True
    assert dq["malformed_count"] >= 0
    assert len(dq["sources"]) >= 3


def test_api_benchmarks_endpoint():
    bench = get_benchmarks()
    assert "metrics" in bench
    assert bench["metrics"]["detection_recall_pct"] >= 90.0
    assert len(bench["stages"]) >= 8
