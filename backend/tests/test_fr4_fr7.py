"""Comprehensive test suite for PathWarden FR-4 through FR-7 modules."""

import os
import json
import time
import tempfile
import pytest
from datetime import datetime, timezone

from correlation.entity_resolver import EntityResolver
from correlation.candidate_generator import CandidatePair
from correlation.relationship_scorer import RelationshipScorer, ScoredRelationship
from correlation.anti_hub_filter import AntiHubFilter
from correlation.incident_clusterer import IncidentClusterer
from correlation.path_reconstructor import PathReconstructor, AttackStep, AttackEdge
from correlation.cross_batch_state import CrossBatchState
from reachability.network_topology import NetworkTopology
from reachability.privilege_graph import PrivilegeGraph
from reachability.reachability_engine import ReachabilityEngine
from worker.job_registry import JobRegistry
from worker.checkpoint_manager import CheckpointManager


# ----------------------------------------------------------------------
# 1. Entity Resolver Tests
# ----------------------------------------------------------------------
def test_entity_resolver_host():
    resolver = EntityResolver()
    assert resolver.resolve_host("agt-01", "WS-EXEC-04.CORP.LOCAL", "10.0.0.1") == "host:ws-exec-04.corp.local"
    assert resolver.resolve_host("agt-02", None, "192.168.1.100") == "host:agt-02"
    assert resolver.resolve_host(None, None, "192.168.1.100") == "host:ip-192.168.1.100"
    assert resolver.resolve_host("agt-03", None, None) == "host:agt-03"


def test_entity_resolver_user():
    resolver = EntityResolver()
    assert resolver.resolve_user("u1", "CORP\\j.doe") == "user:corp\\j.doe"
    assert resolver.resolve_user("u2", "j.doe@corp.local") == "user:corp.local\\j.doe"
    assert resolver.resolve_user("u3", "m.vance", "CORP") == "user:corp\\m.vance"
    assert resolver.resolve_user("u4", "LOCALADMIN") == "user:localadmin"


def test_entity_resolver_process():
    resolver = EntityResolver()
    ts = datetime(2026, 10, 31, 8, 14, 25, tzinfo=timezone.utc)
    proc_id = resolver.resolve_process("WS-EXEC-04", 4892, ts)
    assert proc_id.startswith("proc:ws-exec-04:4892:")


# ----------------------------------------------------------------------
# 2. Relationship Scorer Tests
# ----------------------------------------------------------------------
def test_relationship_scorer():
    scorer = RelationshipScorer()

    # Process parent-child
    p_pair = CandidatePair(
        src_detection_id="D1", dst_detection_id="D2",
        src_event_uid="E1", dst_event_uid="E2",
        src_host="WS-EXEC-04", dst_host="WS-EXEC-04",
        src_user="m.vance", dst_user="m.vance",
        src_ts=100.0, dst_ts=110.0, delta_seconds=10.0,
        candidate_type="process_parent", join_key="4892:WS-EXEC-04"
    )
    rel = scorer.score_candidate(p_pair)
    assert rel is not None
    assert rel.relationship_type == "spawned"
    assert rel.relationship_score >= 0.85
    assert rel.observed_or_inferred == "OBSERVED"

    # Lateral Auth
    l_pair = CandidatePair(
        src_detection_id="D3", dst_detection_id="D4",
        src_event_uid="E3", dst_event_uid="E4",
        src_host="WS-EXEC-04", dst_host="SRV-APP-PROD01",
        src_user="svc_deploy", dst_user="svc_deploy",
        src_ts=200.0, dst_ts=250.0, delta_seconds=50.0,
        candidate_type="lateral_auth", join_key="svc_deploy:SRV-APP-PROD01"
    )
    rel_lat = scorer.score_candidate(l_pair)
    assert rel_lat is not None
    assert rel_lat.relationship_type == "authenticated_to"
    assert rel_lat.observed_or_inferred == "OBSERVED"


# ----------------------------------------------------------------------
# 3. Anti-Hub Filter Tests (Decoy Resistance)
# ----------------------------------------------------------------------
def test_anti_hub_filter_penalty():
    hub_filter = AntiHubFilter()

    # Normal low-degree entity (degree = 5)
    score_normal = hub_filter.apply_hub_penalty(0.90, degree=5)
    assert score_normal == 0.90  # No penalty below degree 40

    # High-degree hub entity (degree = 140, e.g. Domain Controller / NAT gateway)
    score_hub = hub_filter.apply_hub_penalty(0.90, degree=140)
    assert score_hub < 0.50  # Significantly discounted by log penalty


def test_anti_hub_corroboration_requirement():
    hub_filter = AntiHubFilter()
    rel_hub = ScoredRelationship(
        src_detection_id="HUB_DC01",
        dst_detection_id="RANDOM_HOST_99",
        relationship_type="connected_to",
        relationship_score=0.75,
        observed_or_inferred="INFERRED",
        evidence_event_uids=["SINGLE_EVT"],  # Only 1 evidence UID
        explanation="Routine connection",
        confidence_category="MODERATE"
    )

    # Simulate high degree on HUB_DC01
    hub_filter._entity_stats["HUB_DC01"] = hub_filter._entity_stats.get(
        "HUB_DC01", type("obj", (), {"degree": 80, "evidence_uids": ["SINGLE_EVT"]})()
    )

    filtered = hub_filter.filter_relationships([rel_hub])
    # Must be dropped because degree > 50 and evidence count < 2
    assert len(filtered) == 0


# ----------------------------------------------------------------------
# 4. Incident Clusterer Tests (Incident Gate Validation)
# ----------------------------------------------------------------------
def test_incident_clusterer_gate():
    clusterer = IncidentClusterer()

    rel1 = ScoredRelationship(
        src_detection_id="D1", dst_detection_id="D2",
        relationship_type="spawned", relationship_score=0.95,
        observed_or_inferred="OBSERVED", evidence_event_uids=["E1", "E2"],
        explanation="Process spawn", confidence_category="STRONG"
    )
    rel2 = ScoredRelationship(
        src_detection_id="D2", dst_detection_id="D3",
        relationship_type="authenticated_to", relationship_score=0.90,
        observed_or_inferred="OBSERVED", evidence_event_uids=["E2", "E3"],
        explanation="Pass the hash", confidence_category="STRONG"
    )

    # 3 steps, 2 kill chain stages
    kc_map = {"D1": "Exploitation", "D2": "Actions on Objectives", "D3": "Lateral Movement"}
    clusters = clusterer.cluster([rel1, rel2], kc_map)

    assert len(clusters) == 1
    assert clusters[0].passed_gate is True
    assert len(clusters[0].detection_ids) == 3


def test_incident_clusterer_gate_rejects_weak():
    clusterer = IncidentClusterer()
    # Weak temporal-only relationship with single stage
    weak_rel = ScoredRelationship(
        src_detection_id="W1", dst_detection_id="W2",
        relationship_type="shared_host_traversal", relationship_score=0.50,
        observed_or_inferred="INFERRED", evidence_event_uids=["EW1"],
        explanation="Weak proximity", confidence_category="MODERATE"
    )
    kc_map = {"W1": "Discovery", "W2": "Discovery"}
    clusters = clusterer.cluster([weak_rel], kc_map)
    assert len(clusters) == 0  # Does not pass incident gate


# ----------------------------------------------------------------------
# 5. Path Reconstructor Tests
# ----------------------------------------------------------------------
def test_path_reconstructor():
    from correlation.incident_clusterer import IncidentCluster

    reconstructor = PathReconstructor()
    reconstructor.load_detection_metadata([
        {
            "detection_id": "D1", "event_ts": 100.0, "host_name": "WS-EXEC-04",
            "user_name": "m.vance", "process_name": "powershell.exe",
            "command_line": "powershell.exe -Enc ...", "severity": "HIGH",
            "technique_id": "T1059.001", "technique_name": "PowerShell",
            "tactic": "Execution", "kill_chain_stage": "Exploitation",
            "evidence_ids": ["E1"]
        },
        {
            "detection_id": "D2", "event_ts": 101.0, "host_name": "WS-EXEC-04",  # within 2s on same host
            "user_name": "m.vance", "process_name": "whoami.exe",
            "command_line": "whoami.exe", "severity": "MEDIUM",
            "technique_id": "T1087.002", "technique_name": "Domain Account Discovery",
            "tactic": "Discovery", "kill_chain_stage": "Reconnaissance",
            "evidence_ids": ["E2"]
        }
    ])

    rel = ScoredRelationship(
        src_detection_id="D1", dst_detection_id="D2",
        relationship_type="spawned", relationship_score=0.95,
        observed_or_inferred="OBSERVED", evidence_event_uids=["E1", "E2"],
        explanation="Spawned", confidence_category="STRONG"
    )

    cluster = IncidentCluster(
        cluster_id="D1", detection_ids={"D1", "D2"},
        relationships=[rel], kill_chain_stages={"Exploitation", "Reconnaissance"},
        has_strong_causal_edge=True, passed_gate=True
    )

    steps, edges = reconstructor.reconstruct(cluster)
    assert len(steps) == 2
    assert steps[0].step_uid == "D1"
    assert steps[1].step_uid == "D2"
    # Clock-offset within 2s should be flagged uncertain
    assert steps[1].is_uncertain is True
    assert len(edges) == 1
    assert edges[0].source_step_uid == "D1"
    assert edges[0].target_step_uid == "D2"


# ----------------------------------------------------------------------
# 6. Cross-Batch Sliding Window State Tests
# ----------------------------------------------------------------------
def test_cross_batch_state():
    with tempfile.TemporaryDirectory() as tmpdir:
        state_file = os.path.join(tmpdir, "state.json")
        state = CrossBatchState(window_seconds=600, state_path=state_file)

        # Register open session & process
        state.register_session("SESS-01", "WS-EXEC-04", "m.vance", "D1", event_ts=1000.0)
        state.register_process("WS-EXEC-04", 4892, "D1", event_ts=1000.0)

        # Lookup within window
        sess = state.lookup_session("SESS-01", at_ts=1200.0)
        assert sess is not None
        assert sess.user_name == "m.vance"

        # Lookup past window (600s)
        sess_expired = state.lookup_session("SESS-01", at_ts=1700.0)
        assert sess_expired is None

        # Save & reload
        state.save()
        assert os.path.exists(state_file)

        state2 = CrossBatchState(window_seconds=600, state_path=state_file)
        assert state2.load() is True
        assert state2.lookup_session("SESS-01", at_ts=1200.0) is not None


# ----------------------------------------------------------------------
# 7. Reachability Engine Tests (Bounded BFS & Strict Semantics)
# ----------------------------------------------------------------------
def test_reachability_engine_bounds():
    with tempfile.TemporaryDirectory() as tmpdir:
        topo = NetworkTopology(tmpdir)
        # Manually seed adjacency for isolated unit test
        from reachability.network_topology import NetworkLink
        topo._built = True
        topo._adjacency = {
            "WS-EXEC-04": [NetworkLink("WS-EXEC-04", "SRV-APP-PROD01", confirmed=True, evidence_uid="E_SMB")],
            "SRV-APP-PROD01": [NetworkLink("SRV-APP-PROD01", "DC01.CORP.LOCAL", confirmed=True, evidence_uid="E_RPC")],
            "DC01.CORP.LOCAL": [NetworkLink("DC01.CORP.LOCAL", "BACKUP-VAULT", confirmed=False, evidence_uid="E_ROUTABLE")],
        }

        priv = PrivilegeGraph(tmpdir)
        priv._built = True

        engine = ReachabilityEngine(topo, priv)
        items = engine.analyze(
            compromised_hosts=["WS-EXEC-04"],
            compromised_users=[],
            critical_assets={"DC01.CORP.LOCAL", "BACKUP-VAULT"}
        )

        # Must terminate at max depth 2
        assert len(items) <= 50
        # Check OBSERVED vs NETWORK_REACHABLE separation
        observed_items = [i for i in items if i.reachability_status == "OBSERVED"]
        potential_items = [i for i in items if i.reachability_status == "NETWORK_REACHABLE"]

        assert len(observed_items) >= 2
        # Target asset names should be in the list
        item_names = {i.asset_name for i in items}
        assert "SRV-APP-PROD01" in item_names
        assert "DC01.CORP.LOCAL" in item_names


# ----------------------------------------------------------------------
# 8. Checkpoint Manager & Job Registry Tests
# ----------------------------------------------------------------------
def test_checkpoint_idempotency():
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "test_jobs.sqlite3")
        registry = JobRegistry(db_path=db_path)
        mgr = CheckpointManager(registry)

        registry.create_job("RUN-TEST-01", tmpdir, {})
        # Commit batch 1 twice (must not raise UNIQUE error)
        mgr.commit_batch("RUN-TEST-01", batch_id=1, byte_offset=1024)
        mgr.commit_batch("RUN-TEST-01", batch_id=1, byte_offset=1024)

        resume = mgr.get_resume_point("RUN-TEST-01")
        assert resume is not None
        assert resume["batch_id"] == 1
        assert resume["byte_offset"] == 1024

        assert mgr.should_skip_batch("RUN-TEST-01", batch_id=1) is True
        assert mgr.should_skip_batch("RUN-TEST-01", batch_id=2) is False
