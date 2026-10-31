"""PathWarden FR-4: Relationship scorer.

Converts a CandidatePair into a ScoredRelationship with:
- relationship_type (from controlled vocab in enums.py)
- relationship_score (0.0–1.0, evidence-strength, NOT probability)
- observed_or_inferred (EvidenceStatus enum)
- evidence_event_uids list
- human-readable explanation string

Score table (from FR-4 spec):
  process_parent   → SPAWNED            ≥0.90  OBSERVED
  same_session     → OBSERVED_SESSION   ≥0.85  OBSERVED
  lateral_auth     → AUTHENTICATED_TO   ≥0.75  OBSERVED
  network_follow   → CONNECTED_TO       ≥0.55  INFERRED (no confirmed auth)
  same_host+time   → SHARED_HOST_TRAV   ≥0.50  INFERRED
  same_user x-host → SHARED_CREDENTIAL  ≥0.30  POTENTIAL  (only with corroboration)
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List

from common.enums import RelationshipType, EvidenceStatus
from common.logger import get_logger
from .candidate_generator import CandidatePair

logger = get_logger("RelationshipScorer")

# Minimum score below which a relationship is discarded entirely
_MIN_SCORE_THRESHOLD = 0.25


@dataclass
class ScoredRelationship:
    src_detection_id: str
    dst_detection_id: str
    relationship_type: str          # RelationshipType.value
    relationship_score: float       # 0.0–1.0
    observed_or_inferred: str       # EvidenceStatus.value
    evidence_event_uids: List[str]
    explanation: str
    confidence_category: str        # STRONG | MODERATE | INFERRED


class RelationshipScorer:
    """Converts CandidatePair → ScoredRelationship using evidence priority table."""

    def score_candidate(self, pair: CandidatePair) -> ScoredRelationship | None:
        """Return a ScoredRelationship or None if below threshold."""
        ctype = pair.candidate_type

        if ctype == "process_parent":
            return self._score_process_parent(pair)
        elif ctype == "same_session":
            return self._score_same_session(pair)
        elif ctype == "lateral_auth":
            return self._score_lateral_auth(pair)
        elif ctype == "network_follow":
            return self._score_network_follow(pair)
        elif ctype == "same_host_time":
            return self._score_same_host_time(pair)
        else:
            logger.warning("Unknown candidate_type %s — skipping", ctype)
            return None

    # ------------------------------------------------------------------
    # Per-type scorers
    # ------------------------------------------------------------------

    def _score_process_parent(self, pair: CandidatePair) -> ScoredRelationship:
        # Base score: 0.92, decay linearly with delta up to 30s window
        base = 0.92
        score = max(0.75, base - (pair.delta_seconds / 300) * 0.12)
        return ScoredRelationship(
            src_detection_id=pair.src_detection_id,
            dst_detection_id=pair.dst_detection_id,
            relationship_type=RelationshipType.SPAWNED.value,
            relationship_score=round(score, 4),
            observed_or_inferred=EvidenceStatus.OBSERVED.value,
            evidence_event_uids=list(pair.raw_evidence_uids),
            explanation=(
                f"Process parentage: PID {pair.join_key.split(':')[0]} on {pair.src_host} "
                f"spawned child detection Δt={pair.delta_seconds:.1f}s"
            ),
            confidence_category="STRONG" if score >= 0.85 else "MODERATE",
        )

    def _score_same_session(self, pair: CandidatePair) -> ScoredRelationship:
        base = 0.87
        score = max(0.70, base - (pair.delta_seconds / 300) * 0.10)
        return ScoredRelationship(
            src_detection_id=pair.src_detection_id,
            dst_detection_id=pair.dst_detection_id,
            relationship_type=RelationshipType.OBSERVED_SESSION.value,
            relationship_score=round(score, 4),
            observed_or_inferred=EvidenceStatus.OBSERVED.value,
            evidence_event_uids=list(pair.raw_evidence_uids),
            explanation=(
                f"Shared session_id={pair.join_key!r}: "
                f"{pair.src_host}/{pair.src_user} → {pair.dst_host}/{pair.dst_user} "
                f"Δt={pair.delta_seconds:.1f}s"
            ),
            confidence_category="STRONG" if score >= 0.80 else "MODERATE",
        )

    def _score_lateral_auth(self, pair: CandidatePair) -> ScoredRelationship:
        base = 0.78
        score = max(0.55, base - (pair.delta_seconds / 300) * 0.15)
        # Cross-host same-user bumps score
        if pair.src_host != pair.dst_host and pair.src_user == pair.dst_user:
            score = min(0.92, score + 0.08)
        return ScoredRelationship(
            src_detection_id=pair.src_detection_id,
            dst_detection_id=pair.dst_detection_id,
            relationship_type=RelationshipType.AUTHENTICATED_TO.value,
            relationship_score=round(score, 4),
            observed_or_inferred=EvidenceStatus.OBSERVED.value,
            evidence_event_uids=list(pair.raw_evidence_uids),
            explanation=(
                f"Lateral auth: {pair.src_user}@{pair.src_host} → dst_ip matches "
                f"{pair.dst_host}, subsequent activity Δt={pair.delta_seconds:.1f}s"
            ),
            confidence_category="STRONG" if score >= 0.75 else "MODERATE",
        )

    def _score_network_follow(self, pair: CandidatePair) -> ScoredRelationship:
        # No confirmed authentication — score is lower, status is INFERRED
        base = 0.58
        score = max(0.30, base - (pair.delta_seconds / 300) * 0.18)
        if score < _MIN_SCORE_THRESHOLD:
            return None  # type: ignore[return-value]
        return ScoredRelationship(
            src_detection_id=pair.src_detection_id,
            dst_detection_id=pair.dst_detection_id,
            relationship_type=RelationshipType.CONNECTED_TO.value,
            relationship_score=round(score, 4),
            observed_or_inferred=EvidenceStatus.INFERRED.value,
            evidence_event_uids=list(pair.raw_evidence_uids),
            explanation=(
                f"Network connection: {pair.src_host} → {pair.dst_host} "
                f"(no confirmed auth), followed by activity Δt={pair.delta_seconds:.1f}s"
            ),
            confidence_category="MODERATE" if score >= 0.50 else "INFERRED",
        )

    def _score_same_host_time(self, pair: CandidatePair) -> ScoredRelationship:
        base = 0.78
        score = max(0.50, base - (pair.delta_seconds / 300) * 0.15)
        return ScoredRelationship(
            src_detection_id=pair.src_detection_id,
            dst_detection_id=pair.dst_detection_id,
            relationship_type="shared_host_traversal",
            relationship_score=round(score, 4),
            observed_or_inferred=EvidenceStatus.INFERRED.value,
            evidence_event_uids=list(pair.raw_evidence_uids),
            explanation=(
                f"Temporal correlation on host {pair.src_host}: activity within Δt={pair.delta_seconds:.1f}s"
            ),
            confidence_category="STRONG" if score >= 0.75 else "MODERATE",
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def categorize(score: float) -> str:
        if score >= 0.75:
            return "STRONG"
        elif score >= 0.50:
            return "MODERATE"
        return "INFERRED"

