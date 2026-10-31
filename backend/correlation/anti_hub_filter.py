"""PathWarden FR-4: Anti-hub filter.

High-degree entities (Domain Controllers, NAT gateways) appear on many edges
purely because all traffic routes through them.  Without penalty these would
incorrectly merge unrelated incidents into one giant cluster.

Formula (from spec):
    penalised_score = score * (1 / (1 + log10(max(1, degree - 40))))

Entities with degree > 50 additionally require ≥ 2 corroborating evidence UIDs
before their edges are considered incident-forming.
"""

from __future__ import annotations

import math
from typing import Dict, List
from dataclasses import dataclass

from .candidate_generator import CandidatePair
from .relationship_scorer import ScoredRelationship
from common.logger import get_logger

logger = get_logger("AntiHubFilter")

# Degree above which log-penalty kicks in
_HUB_DEGREE_THRESHOLD = 40
# Degree above which corroborating evidence is REQUIRED
_CORROBORATION_DEGREE = 50
# Minimum corroborating evidence count for high-degree hubs
_MIN_CORROBORATION = 2


@dataclass
class EntityStats:
    entity_id: str
    degree: int = 0
    evidence_uids: List[str] = None  # type: ignore[assignment]

    def __post_init__(self):
        if self.evidence_uids is None:
            self.evidence_uids = []


class AntiHubFilter:
    """Calculates per-entity degree and applies log-discount penalty to relationship scores."""

    def __init__(self) -> None:
        self._entity_stats: Dict[str, EntityStats] = {}

    # ------------------------------------------------------------------
    # Build degree map from all scored relationships
    # ------------------------------------------------------------------

    def build_degree_map(self, relationships: List[ScoredRelationship]) -> None:
        """Compute entity degree from the full relationship list.

        Call this once before filter_relationships().
        """
        self._entity_stats.clear()
        for rel in relationships:
            for eid in (rel.src_detection_id, rel.dst_detection_id):
                stats = self._entity_stats.setdefault(eid, EntityStats(entity_id=eid))
                stats.degree += 1
                stats.evidence_uids.extend(rel.evidence_event_uids)

        hub_count = sum(1 for s in self._entity_stats.values() if s.degree > _HUB_DEGREE_THRESHOLD)
        if hub_count:
            logger.info("AntiHubFilter: %d high-degree hub entities detected", hub_count)

    # ------------------------------------------------------------------
    # Apply penalty
    # ------------------------------------------------------------------

    def filter_relationships(
        self, relationships: List[ScoredRelationship]
    ) -> List[ScoredRelationship]:
        """Return relationships with hub-penalised scores; drop below-threshold entries."""
        output: List[ScoredRelationship] = []
        for rel in relationships:
            penalised = self._apply_penalty(rel)
            if penalised is not None:
                output.append(penalised)
        return output

    def apply_hub_penalty(self, score: float, degree: int) -> float:
        """Public: apply the log-discount formula to a single score."""
        if degree <= _HUB_DEGREE_THRESHOLD:
            return score
        penalty = 1.0 / (1.0 + math.log10(max(1, degree - _HUB_DEGREE_THRESHOLD)))
        return round(score * penalty, 4)

    def calculate_entity_degree(self, entity_id: str) -> int:
        """Return the pre-computed degree for entity_id, or 0 if unknown."""
        return self._entity_stats.get(entity_id, EntityStats(entity_id)).degree

    # ------------------------------------------------------------------
    # Private
    # ------------------------------------------------------------------

    def _apply_penalty(self, rel: ScoredRelationship) -> ScoredRelationship | None:
        src_degree = self.calculate_entity_degree(rel.src_detection_id)
        dst_degree = self.calculate_entity_degree(rel.dst_detection_id)
        max_degree = max(src_degree, dst_degree)

        penalised_score = self.apply_hub_penalty(rel.relationship_score, max_degree)

        # High-degree hub with insufficient corroborating evidence — drop
        if max_degree > _CORROBORATION_DEGREE:
            unique_evidence = set(rel.evidence_event_uids)
            if len(unique_evidence) < _MIN_CORROBORATION:
                logger.debug(
                    "AntiHub: dropping edge %s→%s (degree=%d, evidence=%d)",
                    rel.src_detection_id, rel.dst_detection_id, max_degree, len(unique_evidence)
                )
                return None

        # Build updated dataclass (frozen equivalent — create new)
        import dataclasses
        penalised = dataclasses.replace(rel, relationship_score=penalised_score)
        return penalised

