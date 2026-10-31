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
    assert len(bench["stages"]) >= 5


def test_api_status_machine_specs_and_target_matrix():
    status = get_system_status()
    assert "machine_specifications" in status
    specs = status["machine_specifications"]
    assert specs["cpu_cores"] >= 1
    assert specs["total_ram_gb"] > 0
    assert "storage_engine" in specs

    assert "target_matrix" in status
    targets = status["target_matrix"]
    assert len(targets) == 7
    measures = [t["measure"] for t in targets]
    assert "Detection" in measures
    assert "Correct labels" in measures
    assert "Attack path" in measures
    assert "False alarms" in measures
    assert "Processing time" in measures
    assert "Memory" in measures
    assert "Investigation speed" in measures


def test_bonus_b1_risk_score_sorting():
    incidents = list_incidents()
    assert len(incidents) >= 4
    # Ensure sorted by risk_score DESC: highest risk incident is on top
    risk_scores = [inc.get("risk_score", 0) for inc in incidents]
    assert risk_scores == sorted(risk_scores, reverse=True)
    assert risk_scores[0] >= 80  # Worst one is on top
    # Ensure plain English report is present
    for inc in incidents:
        assert "plain_english_report" in inc
        assert len(inc["plain_english_report"]) > 20


def test_bonus_b4_rules_api():
    from api.routes_rules import get_rules, create_rule, delete_rule, RuleModel
    rules_resp = get_rules()
    assert rules_resp["rules_count"] >= 5
    assert isinstance(rules_resp["rules"], list)

    # Test adding a rule dynamically (config-driven)
    new_rule = RuleModel(
        rule_id="RULE-TEST-B4-001",
        rule_name="Dynamic Sigma PowerShell WebClient Detection",
        rule_version="1.0.0",
        technique_id="T1059.001",
        technique_name="PowerShell",
        severity="HIGH",
        tactic="Execution",
        description="Detects dynamic creation of System.Net.WebClient in CLI",
        query="SELECT event_uid FROM events WHERE command_line LIKE '%Net.WebClient%'",
    )
    res = create_rule(new_rule)
    assert res["status"] == "SUCCESS"

    # Clean up test rule
    del_res = delete_rule("RULE-TEST-B4-001")
    assert del_res["status"] == "SUCCESS"

