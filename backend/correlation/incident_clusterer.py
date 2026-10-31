"""PathWarden FR-4: Disjoint-set (Union-Find) incident clusterer.

Groups ScoredRelationships into incident clusters using Union-Find.
Each cluster is validated against the incident gate before being promoted.

Incident gate (from spec):
  - ≥ 2 distinct kill_chain stages  OR  ≥ 3 correlated steps
  - At least 1 high-confidence (STRONG) non-temporal causal edge
  - NOT connected solely via hub-only edges (anti-hub already handled upstream)
  - Short incidents with strong causal edges MUST pass (don't filter by step count alone)
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Set, Optional

from .relationship_scorer import ScoredRelationship
from common.logger import get_logger

logger = get_logger("IncidentClusterer")

# Minimum relationship_score for an edge to count as "high-confidence causal"
_HIGH_CONFIDENCE_THRESHOLD = 0.75
# Temporal-only types that cannot alone satisfy the gate
_TEMPORAL_ONLY_TYPES = {"same_host_time", "shared_host_traversal"}


@dataclass
class IncidentCluster:
    cluster_id: str
    detection_ids: Set[str] = field(default_factory=set)
    relationships: List[ScoredRelationship] = field(default_factory=list)
    kill_chain_stages: Set[str] = field(default_factory=set)
    has_strong_causal_edge: bool = False
    passed_gate: bool = False


class IncidentClusterer:
    """Union-Find clusterer with incident gate validation."""

    def __init__(self) -> None:
        self._parent: Dict[str, str] = {}
        self._rank: Dict[str, int] = defaultdict(int)
        self._rel_map: Dict[str, List[ScoredRelationship]] = defaultdict(list)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def cluster(
        self,
        relationships: List[ScoredRelationship],
        detection_kill_chains: Optional[Dict[str, str]] = None,
    ) -> List[IncidentCluster]:
        """Return validated IncidentCluster list.

        Args:
            relationships: Hub-penalised, threshold-filtered relationships.
            detection_kill_chains: Optional map of detection_id → kill_chain_stage
                (used for the ≥2 stages gate).
        """
        self._reset()
        kc_map = detection_kill_chains or {}

        for rel in relationships:
            self._union(rel.src_detection_id, rel.dst_detection_id)
            root = self._find(rel.src_detection_id)
            self._rel_map[root].append(rel)

        raw_clusters = self._collect_clusters()
        return self._validate_clusters(raw_clusters, kc_map)

    # ------------------------------------------------------------------
    # Union-Find
    # ------------------------------------------------------------------

    def _find(self, x: str) -> str:
        if self._parent.setdefault(x, x) != x:
            self._parent[x] = self._find(self._parent[x])  # path compression
        return self._parent[x]

    def _union(self, a: str, b: str) -> None:
        ra, rb = self._find(a), self._find(b)
        if ra == rb:
            return
        if self._rank[ra] < self._rank[rb]:
            ra, rb = rb, ra
        self._parent[rb] = ra
        if self._rank[ra] == self._rank[rb]:
            self._rank[ra] += 1

    def _reset(self) -> None:
        self._parent.clear()
        self._rank.clear()
        self._rel_map.clear()

    # ------------------------------------------------------------------
    # Cluster collection & gate validation
    # ------------------------------------------------------------------

    def _collect_clusters(self) -> List[IncidentCluster]:
        """Group all detection_ids by their root."""
        groups: Dict[str, Set[str]] = defaultdict(set)
        for node in self._parent:
            groups[self._find(node)].add(node)

        clusters: List[IncidentCluster] = []
        for root, members in groups.items():
            rels = self._rel_map.get(root, [])
            cluster = IncidentCluster(
                cluster_id=root,
                detection_ids=members,
                relationships=rels,
            )
            clusters.append(cluster)
        return clusters

    def _validate_clusters(
        self, clusters: List[IncidentCluster], kc_map: Dict[str, str]
    ) -> List[IncidentCluster]:
        validated: List[IncidentCluster] = []
        for cluster in clusters:
            # Populate kill chain stages from map
            for did in cluster.detection_ids:
                stage = kc_map.get(did)
                if stage:
                    cluster.kill_chain_stages.add(stage)

            # Check for strong causal edges
            cluster.has_strong_causal_edge = any(
                rel.relationship_score >= _HIGH_CONFIDENCE_THRESHOLD
                and rel.relationship_type not in _TEMPORAL_ONLY_TYPES
                for rel in cluster.relationships
            )

            # Gate evaluation
            step_count = len(cluster.detection_ids)
            stage_count = len(cluster.kill_chain_stages)

            passes = (
                (stage_count >= 2 or step_count >= 3)
                and cluster.has_strong_causal_edge
            )

            # Special pass: strong single-stage incident (e.g. DCSync with clear parent chain)
            if not passes and cluster.has_strong_causal_edge and step_count >= 2:
                strong_score = max(
                    (r.relationship_score for r in cluster.relationships), default=0
                )
                if strong_score >= 0.88:
                    passes = True
                    logger.info(
                        "Cluster %s: gate exception — high-confidence 2-step incident (score=%.2f)",
                        cluster.cluster_id, strong_score
                    )

            cluster.passed_gate = passes
            if passes:
                validated.append(cluster)
            else:
                logger.debug(
                    "Cluster %s failed gate: steps=%d stages=%d strong=%s",
                    cluster.cluster_id, step_count, stage_count, cluster.has_strong_causal_edge
                )
        return validated

