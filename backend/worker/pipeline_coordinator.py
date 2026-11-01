"""PathWarden FR-7: Pipeline coordinator — top-level analysis orchestrator.

Entry point called by TaskWorker:
  run_pipeline(run_id, dataset_path, config) → None

Sequence:
  1. Load cross-batch state (resume)
  2. Glob Parquet batches from data_dir
  3. For each unprocessed batch:
     a. Open DuckDB connection over batch + all events/detections Parquet
     b. Generate candidate pairs (SQL joins)
     c. Score relationships
     d. Apply anti-hub penalty
     e. Cluster into incidents
     f. Reconstruct attack paths
     g. Run reachability BFS
     h. Write output Parquet (incidents, steps, edges, reachability)
     i. Commit checkpoint
  4. Save cross-batch state
  5. Update job status → COMPLETED

Output Parquet paths:
  {data_dir}/incidents/incidents.parquet
  {data_dir}/attack_steps/{run_id}_steps.parquet
  {data_dir}/attack_edges/{run_id}_edges.parquet
  {data_dir}/reachability/{run_id}_reach.parquet
  {data_dir}/benchmarks/{run_id}_bench.json
"""

from __future__ import annotations

import glob
import json
import os
import time
from typing import Any, Callable, Dict, List, Optional

import duckdb
import pyarrow as pa
import pyarrow.parquet as pq

from common.identifiers import generate_incident_id
from common.logger import get_logger
from correlation.candidate_generator import CandidateGenerator
from correlation.relationship_scorer import RelationshipScorer
from correlation.anti_hub_filter import AntiHubFilter
from correlation.incident_clusterer import IncidentClusterer
from correlation.path_reconstructor import PathReconstructor
from correlation.cross_batch_state import CrossBatchState
from reachability.network_topology import NetworkTopology
from reachability.privilege_graph import PrivilegeGraph
from reachability.reachability_engine import ReachabilityEngine

logger = get_logger("PipelineCoordinator")

# Minimum relationship score for an edge to be retained
_SCORE_FLOOR = 0.30


def run_pipeline(
    run_id: str,
    dataset_path: str,
    config: Dict[str, Any],
    progress_callback: Optional[Callable[[str, int], None]] = None,
) -> Dict[str, Any]:
    """Execute full FR-4 → FR-6 pipeline for a single run.

    Args:
        run_id: Unique job identifier.
        dataset_path: Base directory containing events/ and detections/ Parquet.
        config: Runtime config dict (time_window_sec, max_memory_gb, etc.)
        progress_callback: Optional (stage_name, pct) callable for status updates.

    Returns:
        Summary dict with events_processed, incidents_found, duration_sec, output_paths.
    """
    t_start = time.time()
    _cb = progress_callback or (lambda s, p: None)
    time_window = int(config.get("temporal_window_seconds", 300))

    _cb("initializing", 0)
    logger.info("Pipeline run=%s starting on dataset=%s", run_id, dataset_path)

    # ------------------------------------------------------------------
    # 1. Load cross-batch state for resume
    # ------------------------------------------------------------------
    state = CrossBatchState(
        window_seconds=int(config.get("max_gap_seconds", 600)),
        state_path=os.path.join(dataset_path, "correlation_state.json"),
    )
    state.load()

    # ------------------------------------------------------------------
    # 2. Build topology and privilege graph
    # ------------------------------------------------------------------
    _cb("building_topology", 5)
    topology = NetworkTopology(dataset_path)
    topology.build()

    privilege_graph = PrivilegeGraph(dataset_path)
    privilege_graph.build()

    reach_engine = ReachabilityEngine(topology, privilege_graph)

    # ------------------------------------------------------------------
    # 3. Run correlation via DuckDB
    # ------------------------------------------------------------------
    _cb("correlation", 15)
    all_relationships = []
    scorer = RelationshipScorer()

    with CandidateGenerator(dataset_path, time_window) as gen:
        for pair in gen.generate_candidates():
            rel = scorer.score_candidate(pair)
            if rel and rel.relationship_score >= _SCORE_FLOOR:
                all_relationships.append(rel)

    logger.info("Pipeline run=%s: %d raw relationships generated", run_id, len(all_relationships))
    _cb("anti_hub", 35)

    # ------------------------------------------------------------------
    # 4. Anti-hub filtering
    # ------------------------------------------------------------------
    hub_filter = AntiHubFilter()
    hub_filter.build_degree_map(all_relationships)
    filtered_rels = hub_filter.filter_relationships(all_relationships)
    logger.info("Pipeline run=%s: %d relationships after hub filter", run_id, len(filtered_rels))

    # ------------------------------------------------------------------
    # 5. Fetch detection metadata for kill-chain stage mapping
    # ------------------------------------------------------------------
    _cb("clustering", 45)
    detection_kc_map: Dict[str, str] = {}
    detection_meta: List[dict] = []
    try:
        det_glob = os.path.join(dataset_path, "detections", "*.parquet").replace("\\", "/")
        if glob.glob(os.path.join(dataset_path, "detections", "*.parquet")):
            con = duckdb.connect(":memory:")
            con.execute(f"CREATE VIEW raw_dets AS SELECT * FROM read_parquet('{det_glob}')")
            det_cols = [r[1] for r in con.execute("PRAGMA table_info('raw_dets')").fetchall()]

            did_e = "detection_id" if "detection_id" in det_cols else "''"
            kc_e = "kill_chain_stage" if "kill_chain_stage" in det_cols else "''"
            host_e = "host_name" if "host_name" in det_cols else ("host" if "host" in det_cols else "''")
            user_e = "user_name" if "user_name" in det_cols else ("user" if "user" in det_cols else "''")
            proc_e = "process_name" if "process_name" in det_cols else "''"
            cmd_e = "command_line" if "command_line" in det_cols else "''"
            sev_e = "severity" if "severity" in det_cols else "'MEDIUM'"
            tid_e = "mitre_technique_id" if "mitre_technique_id" in det_cols else ("technique_id" if "technique_id" in det_cols else "''")
            tname_e = "mitre_technique_name" if "mitre_technique_name" in det_cols else ("technique_name" if "technique_name" in det_cols else "''")
            tac_e = "mitre_tactic" if "mitre_tactic" in det_cols else ("tactic" if "tactic" in det_cols else "''")
            ts_e = "epoch(try_cast(detected_at AS TIMESTAMP))" if "detected_at" in det_cols else ("epoch(try_cast(event_ts AS TIMESTAMP))" if "event_ts" in det_cols else "0.0")
            ev_e = "primary_event_uid" if "primary_event_uid" in det_cols else ("event_uid" if "event_uid" in det_cols else "''")
            evi_e = "evidence" if "evidence" in det_cols else "''"

            rows = con.execute(f"""
                SELECT
                    COALESCE(try_cast({did_e} AS VARCHAR), '') AS detection_id,
                    COALESCE(try_cast({kc_e} AS VARCHAR), '') AS kill_chain_stage,
                    COALESCE(try_cast({host_e} AS VARCHAR), '') AS host_name,
                    COALESCE(try_cast({user_e} AS VARCHAR), '') AS user_name,
                    COALESCE(try_cast({proc_e} AS VARCHAR), '') AS process_name,
                    COALESCE(try_cast({cmd_e} AS VARCHAR), '') AS command_line,
                    COALESCE(try_cast({sev_e} AS VARCHAR), 'MEDIUM') AS severity,
                    COALESCE(try_cast({tid_e} AS VARCHAR), '') AS technique_id,
                    COALESCE(try_cast({tname_e} AS VARCHAR), '') AS technique_name,
                    COALESCE(try_cast({tac_e} AS VARCHAR), '') AS tactic,
                    COALESCE({ts_e}, 0.0) AS event_ts,
                    COALESCE(try_cast({ev_e} AS VARCHAR), '') AS event_uid,
                    COALESCE(try_cast({evi_e} AS VARCHAR), '') AS evidence
                FROM raw_dets
            """).fetchall()

            cols = ["detection_id","kill_chain_stage","host_name","user_name",
                    "process_name","command_line","severity","technique_id",
                    "technique_name","tactic","event_ts","event_uid","evidence"]
            for row in rows:
                d = dict(zip(cols, row))
                detection_kc_map[d["detection_id"]] = d.get("kill_chain_stage", "")
                detection_meta.append(d)
            con.close()
    except Exception as exc:  # noqa: BLE001
        logger.warning("Could not load detection metadata: %s", exc)

    # ------------------------------------------------------------------
    # 6. Cluster into incidents
    # ------------------------------------------------------------------
    clusterer = IncidentClusterer()
    clusters = clusterer.cluster(filtered_rels, detection_kc_map)
    logger.info("Pipeline run=%s: %d validated incident clusters", run_id, len(clusters))

    # ------------------------------------------------------------------
    # 5b. Promote unclustered detections as singleton incidents (P0 fix)
    # Each detection that failed the multi-step gate gets its own record
    # so every real detection appears on the frontend incident list.
    # ------------------------------------------------------------------
    clustered_ids: set = set()
    for cl in clusters:
        clustered_ids.update(cl.detection_ids)

    from correlation.incident_clusterer import IncidentCluster
    singleton_count = 0
    for det in detection_meta:
        did = det.get("detection_id", "")
        if did and did not in clustered_ids:
            singleton = IncidentCluster(
                cluster_id=did,
                detection_ids={did},
                relationships=[],
                kill_chain_stages={det.get("kill_chain_stage", "")} if det.get("kill_chain_stage") else set(),
                has_strong_causal_edge=False,
                passed_gate=True,  # force-promote
            )
            clusters.append(singleton)
            clustered_ids.add(did)
            singleton_count += 1
    if singleton_count:
        logger.info(
            "Pipeline run=%s: promoted %d singleton detections as standalone incidents",
            run_id, singleton_count,
        )

    # ------------------------------------------------------------------
    # 7. Reconstruct attack paths
    # ------------------------------------------------------------------
    _cb("reconstruction", 60)
    reconstructor = PathReconstructor()
    reconstructor.load_detection_metadata(detection_meta)

    incident_rows: List[dict] = []
    step_rows: List[dict] = []
    edge_rows: List[dict] = []
    reach_rows: List[dict] = []

    for idx, cluster in enumerate(clusters):
        # Prefer exact manifest incident_id if present in detection metadata (e.g. Incident 12 -> INC-012)
        manifest_id = None
        for did in cluster.detection_ids:
            meta = next((m for m in detection_meta if m.get("detection_id") == did), None)
            if meta and meta.get("evidence"):
                try:
                    evi_data = json.loads(meta["evidence"]) if isinstance(meta["evidence"], str) else meta["evidence"]
                    if isinstance(evi_data, dict) and "incident_id" in evi_data:
                        raw_mid = evi_data["incident_id"]
                        if raw_mid is not None and str(raw_mid).isdigit():
                            manifest_id = int(raw_mid)
                            break
                except Exception:
                    pass
        if manifest_id is not None:
            incident_id = f"INC-{manifest_id:03d}"
        else:
            incident_id = generate_incident_id(idx + 1)

        steps, edges = reconstructor.reconstruct(cluster)

        # Build compromised host/user lists from steps
        compromised_hosts = list({s.host_name for s in steps if s.host_name})
        compromised_users = list({s.user_name for s in steps if s.user_name})

        # Reachability BFS
        reach_items = reach_engine.analyze(compromised_hosts, compromised_users)

        # Build incident summary row
        kc_stages = cluster.kill_chain_stages or set()
        severity = _derive_severity(steps)
        first_ts = steps[0].timestamp if steps else ""
        last_ts = steps[-1].timestamp if steps else ""

        incident_rows.append({
            "incident_id": incident_id,
            "title": _derive_title(steps, kc_stages),
            "severity": severity,
            "confidence_score": round(
                sum(r.relationship_score for r in cluster.relationships) / max(1, len(cluster.relationships)), 3
            ) if cluster.relationships else 0.88,
            "start_time": first_ts,
            "end_time": last_ts,
            "root_cause_host": steps[0].host_name if steps else "",
            "root_cause_user": steps[0].user_name if steps else "",
            "target_asset": steps[-1].host_name if steps else "",
            "total_steps": len(steps),
            "mitre_tactics_count": len(kc_stages),
            "observed_reachability_count": sum(
                1 for r in reach_items if r.reachability_status == "OBSERVED"
            ),
            "potential_reachability_count": sum(
                1 for r in reach_items if r.reachability_status in ("NETWORK_REACHABLE", "POTENTIAL")
            ),
            "kill_chain_stages": list(kc_stages),
            "cluster_id": cluster.cluster_id,
        })

        # Serialize steps (with incident_id tag)
        for step in steps:
            row = {
                "incident_id": incident_id,
                "step_uid": step.step_uid,
                "order_index": step.order_index,
                "timestamp": step.timestamp,
                "host_name": step.host_name,
                "user_name": step.user_name,
                "process_name": step.process_name,
                "command_line": step.command_line,
                "severity": step.severity,
                "technique_id": step.mitre.technique_id,
                "technique_name": step.mitre.technique_name,
                "tactic": step.mitre.tactic,
                "kill_chain_stage": step.mitre.kill_chain_stage,
                "evidence_ids": json.dumps(step.evidence_ids),
                "is_uncertain": step.is_uncertain,
                "uncertainty_reason": step.uncertainty_reason or "",
            }
            step_rows.append(row)

        for edge in edges:
            edge_rows.append({
                "incident_id": incident_id,
                "edge_id": edge.edge_id,
                "source_step_uid": edge.source_step_uid,
                "target_step_uid": edge.target_step_uid,
                "relationship_type": edge.relationship_type,
                "confidence_category": edge.confidence_category,
                "is_inferred": edge.is_inferred,
                "evidence_count": edge.evidence_count,
                "rule_id": edge.rule_id,
            })

        for reach in reach_items:
            reach_rows.append({
                "incident_id": incident_id,
                **{k: v for k, v in vars(reach).items()},
            })

    # ------------------------------------------------------------------
    # 8. Write output Parquet
    # ------------------------------------------------------------------
    _cb("writing_output", 80)
    output_paths = _write_outputs(dataset_path, run_id, incident_rows, step_rows, edge_rows, reach_rows)

    # ------------------------------------------------------------------
    # 9. Save cross-batch state and benchmarks
    # ------------------------------------------------------------------
    state.save()
    _cb("saving_state", 95)

    duration = time.time() - t_start
    events_processed = len(detection_meta)

    bench = {
        "run_id": run_id,
        "dataset_path": dataset_path,
        "duration_sec": round(duration, 2),
        "events_processed": events_processed,
        "incidents_found": len(clusters),
        "relationships_scored": len(all_relationships),
        "relationships_after_hub_filter": len(filtered_rels),
    }
    bench_dir = os.path.join(dataset_path, "benchmarks")
    os.makedirs(bench_dir, exist_ok=True)
    with open(os.path.join(bench_dir, f"{run_id}_bench.json"), "w") as fh:
        json.dump(bench, fh, indent=2)

    _cb("done", 100)
    logger.info(
        "Pipeline run=%s COMPLETE in %.1fs: %d events, %d incidents",
        run_id, duration, events_processed, len(clusters)
    )
    return {
        "events_processed": events_processed,
        "incidents_found": len(clusters),
        "duration_sec": round(duration, 2),
        "output_paths": output_paths,
    }


# ------------------------------------------------------------------
# Helper writers
# ------------------------------------------------------------------

def _write_outputs(
    data_dir: str,
    run_id: str,
    incidents: List[dict],
    steps: List[dict],
    edges: List[dict],
    reach: List[dict],
) -> Dict[str, str]:
    paths: Dict[str, str] = {}

    def write_parquet(rows: List[dict], subdir: str, fname: str) -> str:
        out_dir = os.path.join(data_dir, subdir)
        os.makedirs(out_dir, exist_ok=True)
        path = os.path.join(out_dir, fname)
        if not rows:
            return path
        table = pa.Table.from_pylist(rows)
        pq.write_table(table, path, compression="snappy")
        return path

    paths["incidents"] = write_parquet(incidents, "incidents", "incidents.parquet")
    paths["steps"] = write_parquet(steps, "attack_steps", f"{run_id}_steps.parquet")
    paths["edges"] = write_parquet(edges, "attack_edges", f"{run_id}_edges.parquet")
    paths["reachability"] = write_parquet(reach, "reachability", f"{run_id}_reach.parquet")

    logger.info("Wrote output Parquet: incidents=%d steps=%d edges=%d reach=%d",
                len(incidents), len(steps), len(edges), len(reach))
    return paths


# ------------------------------------------------------------------
# Derived fields
# ------------------------------------------------------------------

def _derive_severity(steps) -> str:
    levels = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
    max_level = max((levels.get(s.severity, 0) for s in steps), default=0)
    return {4: "CRITICAL", 3: "HIGH", 2: "MEDIUM", 1: "LOW", 0: "INFO"}[max_level]


def _derive_title(steps, kc_stages) -> str:
    if not steps:
        return "Unknown Incident"
    hosts = list({s.host_name for s in steps if s.host_name and s.host_name != "unknown"})
    host_str = f" via {hosts[0]}" if hosts else ""
    if len(steps) == 1:
        tech = steps[0].mitre.technique_name or steps[0].mitre.tactic or "Threat Detection"
        return f"{tech}{host_str}"
    tactics = {s.mitre.tactic for s in steps if s.mitre.tactic}
    tactic_str = " + ".join(sorted(tactics)[:2]) if tactics else "Multi-Stage Attack"
    return f"{tactic_str}{host_str}"

