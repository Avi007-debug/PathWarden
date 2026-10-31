"""PathWarden FR-4: Attack path reconstructor.

Converts a validated IncidentCluster into:
  - Chronological timeline (sorted by event_ts)
  - Causal DAG (directed, no cycles, clock-offset events flagged TIMESTAMP_UNCERTAIN)
  - AttackStep and AttackEdge output records matching frontend TypeScript types exactly

Frontend contract (from client.ts / types.ts):
  AttackStep:
    step_uid, order_index, timestamp, host_name, user_name, process_name,
    command_line, severity, mitre{technique_id, technique_name, tactic, kill_chain_stage},
    evidence_ids, is_uncertain, uncertainty_reason

  AttackEdge:
    edge_id, source_step_uid, target_step_uid, relationship_type,
    confidence_category, is_inferred, evidence_count, rule_id
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Set, Tuple

from .incident_clusterer import IncidentCluster
from .relationship_scorer import ScoredRelationship
from detection.network_threat_monitor import network_threat_monitor, NetworkThreatInfo
from common.enums import EvidenceStatus
from common.logger import get_logger

logger = get_logger("PathReconstructor")

# Clock-skew tolerance: events within this window on the same host are considered
# simultaneous and order is determined by causal parentage not timestamp.
_CLOCK_TOLERANCE_SECONDS = 2.0


@dataclass
class MitreDetail:
    technique_id: str = ""
    technique_name: str = ""
    tactic: str = ""
    kill_chain_stage: str = ""


@dataclass
class AttackStep:
    step_uid: str
    order_index: int
    timestamp: str          # ISO-8601
    host_name: str
    user_name: str
    process_name: str
    command_line: str
    severity: str
    mitre: MitreDetail
    evidence_ids: List[str] = field(default_factory=list)
    is_uncertain: bool = False
    uncertainty_reason: Optional[str] = None
    network_threat: Optional[NetworkThreatInfo] = None


@dataclass
class AttackEdge:
    edge_id: str
    source_step_uid: str
    target_step_uid: str
    relationship_type: str
    confidence_category: str
    is_inferred: bool
    evidence_count: int
    rule_id: str


class PathReconstructor:
    """Converts IncidentCluster + detection metadata into ordered AttackStep/AttackEdge lists."""

    def __init__(self) -> None:
        self._detection_meta: Dict[str, dict] = {}

    def load_detection_metadata(self, meta_rows: List[dict]) -> None:
        """Pre-load detection metadata rows (from DuckDB query) keyed by detection_id."""
        for row in meta_rows:
            did = row.get("detection_id", "")
            if did:
                self._detection_meta[did] = row

    def reconstruct(
        self, cluster: IncidentCluster
    ) -> Tuple[List[AttackStep], List[AttackEdge]]:
        """Return (steps, edges) for a single IncidentCluster."""
        steps = self._build_steps(cluster)
        edges = self._build_edges(cluster, steps)
        return steps, edges

    # ------------------------------------------------------------------
    # Step construction
    # ------------------------------------------------------------------

    def _build_steps(self, cluster: IncidentCluster) -> List[AttackStep]:
        raw: List[dict] = []
        for did in cluster.detection_ids:
            meta = self._detection_meta.get(did, {})
            raw.append({"detection_id": did, **meta})

        # Sort chronologically by event_ts (float epoch seconds)
        raw.sort(key=lambda r: float(r.get("event_ts", 0)))

        steps: List[AttackStep] = []
        seen_ts: Dict[str, float] = {}  # host → last ts, for clock-skew detection

        for idx, row in enumerate(raw):
            did = row.get("detection_id", "")
            host = row.get("host_name", "unknown")
            ts_epoch = float(row.get("event_ts", 0))
            ts_str = row.get("timestamp") or self._epoch_to_iso(ts_epoch)

            # Clock-skew detection: same host, almost identical timestamp
            is_uncertain = False
            uncertainty_reason: Optional[str] = None
            prev_ts = seen_ts.get(host)
            if prev_ts is not None and abs(ts_epoch - prev_ts) < _CLOCK_TOLERANCE_SECONDS:
                is_uncertain = True
                uncertainty_reason = (
                    f"Events within {_CLOCK_TOLERANCE_SECONDS}s on same host "
                    f"{host!r}; causal order inferred from parentage"
                )
            seen_ts[host] = ts_epoch

            step = AttackStep(
                step_uid=did,
                order_index=idx + 1,
                timestamp=ts_str,
                host_name=host,
                user_name=row.get("user_name", ""),
                process_name=row.get("process_name", ""),
                command_line=row.get("command_line", ""),
                severity=row.get("severity", "MEDIUM"),
                mitre=MitreDetail(
                    technique_id=row.get("technique_id", ""),
                    technique_name=row.get("technique_name", ""),
                    tactic=row.get("tactic", ""),
                    kill_chain_stage=row.get("kill_chain_stage", ""),
                ),
                evidence_ids=self._parse_evidence_ids(row.get("evidence_ids")),
                is_uncertain=is_uncertain,
                uncertainty_reason=uncertainty_reason,
                network_threat=network_threat_monitor.analyze_step_telemetry(row),
            )
            steps.append(step)

        return steps

    # ------------------------------------------------------------------
    # Edge construction
    # ------------------------------------------------------------------

    def _build_edges(
        self, cluster: IncidentCluster, steps: List[AttackStep]
    ) -> List[AttackEdge]:
        # step_uid → order_index for cycle detection
        uid_to_order: Dict[str, int] = {s.step_uid: s.order_index for s in steps}
        edges: List[AttackEdge] = []
        seen_pairs: Set[Tuple[str, str]] = set()

        for rel in cluster.relationships:
            src_uid = rel.src_detection_id
            dst_uid = rel.dst_detection_id

            # Skip back-edges (would create cycle in DAG)
            src_ord = uid_to_order.get(src_uid, 0)
            dst_ord = uid_to_order.get(dst_uid, 0)
            if dst_ord <= src_ord:
                continue

            pair = (src_uid, dst_uid)
            if pair in seen_pairs:
                continue
            seen_pairs.add(pair)

            edge_id = self._make_edge_id(src_uid, dst_uid)
            edge = AttackEdge(
                edge_id=edge_id,
                source_step_uid=src_uid,
                target_step_uid=dst_uid,
                relationship_type=rel.relationship_type,
                confidence_category=rel.confidence_category,
                is_inferred=(rel.observed_or_inferred == EvidenceStatus.INFERRED.value),
                evidence_count=len(rel.evidence_event_uids),
                rule_id=self._rule_id_from_type(rel.relationship_type),
            )
            edges.append(edge)

        return edges

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _make_edge_id(src: str, dst: str) -> str:
        digest = hashlib.md5(f"{src}:{dst}".encode()).hexdigest()[:8].upper()
        return f"EDGE-{digest}"

    @staticmethod
    def _rule_id_from_type(rel_type: str) -> str:
        mapping = {
            "spawned": "RULE-PARENT-CHILD",
            "observed_session": "RULE-SESSION-CONTINUATION",
            "authenticated_to": "RULE-LATERAL-AUTH",
            "connected_to": "RULE-NETWORK-FOLLOW",
            "shared_host_traversal": "RULE-TEMPORAL-CORRELATION",
            "shared_credential": "RULE-CREDENTIAL-OVERLAP",
            "privilege_relationship": "RULE-PRIVILEGE-GRAPH",
            "network_reachable": "RULE-REACHABILITY-BFS",
        }
        return mapping.get(rel_type, "RULE-GENERIC")

    @staticmethod
    def _epoch_to_iso(epoch: float) -> str:
        from datetime import datetime, timezone
        try:
            return datetime.fromtimestamp(epoch, tz=timezone.utc).isoformat().replace("+00:00", "Z")
        except (OSError, OverflowError, ValueError):
            return "1970-01-01T00:00:00Z"

    @staticmethod
    def _parse_evidence_ids(raw) -> List[str]:
        if not raw:
            return []
        if isinstance(raw, (list, tuple)):
            return [str(e) for e in raw]
        return [str(raw)]

    def to_dict_list(self, steps: List[AttackStep], edges: List[AttackEdge]) -> dict:
        """Serialize to frontend-compatible JSON dict."""
        def step_to_dict(s: AttackStep) -> dict:
            d = asdict(s)
            d["mitre"] = asdict(s.mitre)
            return d

        def edge_to_dict(e: AttackEdge) -> dict:
            return asdict(e)

        return {
            "steps": [step_to_dict(s) for s in steps],
            "edges": [edge_to_dict(e) for e in edges],
        }

