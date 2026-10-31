"""Execute analytical detection rules against DuckDB and produce enriched incident detections."""

from datetime import datetime, timezone
from typing import List, Dict, Any, Optional

from backend.common.identifiers import generate_detection_id
from backend.common.enums import SeverityLevel, ConfidenceCategory
from backend.detection.rule_loader import RuleLoader
from backend.detection.sql_compiler import SQLCompiler
from backend.detection.evidence_collector import EvidenceCollector
from backend.attack_mapping.attack_mapper import AttackMapper


class DetectionEngine:
    """Detection engine evaluating analytical SQL rules and producing MITRE/KC enriched alerts."""

    def __init__(
        self,
        duckdb_manager=None,
        rule_loader: Optional[RuleLoader] = None,
        sql_compiler: Optional[SQLCompiler] = None,
        evidence_collector: Optional[EvidenceCollector] = None,
        attack_mapper: Optional[AttackMapper] = None,
    ):
        self.duck = duckdb_manager
        self.loader = rule_loader or RuleLoader()
        self.compiler = sql_compiler or SQLCompiler()
        self.collector = evidence_collector or EvidenceCollector()
        self.mapper = attack_mapper or AttackMapper()

    def run_rule(self, rule: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Evaluate a single rule against DuckDB and return enriched detections."""
        if not self.duck:
            return []

        detections: List[Dict[str, Any]] = []
        try:
            sql = self.compiler.compile_rule(rule)
            res = self.duck.execute_query(sql)
            if isinstance(res, list):
                rows = res
            elif hasattr(res, "to_dict"):
                rows = res.to_dict(orient="records")
            else:
                rows = []
        except Exception:
            # Query failed (e.g. view not found or empty table)
            return []

        now_iso = datetime.now(timezone.utc).isoformat()
        sev_raw = rule.get("severity", "MEDIUM").upper()
        severity = getattr(SeverityLevel, sev_raw, SeverityLevel.MEDIUM).value

        for row in rows:
            event_uids, primary_uid, evidence = self.collector.extract_evidence_and_uids(row, rule)

            det: Dict[str, Any] = {
                "detection_id": generate_detection_id(),
                "rule_id": rule.get("rule_id", "UNKNOWN_RULE"),
                "rule_name": rule.get("rule_name", "Unknown Rule"),
                "rule_version": rule.get("rule_version", "1.0.0"),
                "event_uids": event_uids,
                "primary_event_uid": primary_uid,
                "detected_at": now_iso,
                "severity": severity,
                "confidence": rule.get("confidence", ConfidenceCategory.STRONG.value),
                "description": rule.get("description", ""),
                "evidence": evidence,
                "mitre_technique_id": rule.get("technique_id"),
                "mitre_technique_name": rule.get("technique_name"),
                "mitre_tactic": rule.get("tactic"),
            }

            # Enrich with ATT&CK and Kill Chain metadata
            self.mapper.enrich(det)
            detections.append(det)

        return detections

    def evaluate_rules(self, rules: Optional[List[Dict[str, Any]]] = None) -> List[Dict[str, Any]]:
        """Evaluate a given list of rules (or all loaded rules if None)."""
        target_rules = rules if rules is not None else self.loader.load_rules()
        all_detections: List[Dict[str, Any]] = []

        for rule in target_rules:
            dets = self.run_rule(rule)
            all_detections.extend(dets)

        return all_detections

    def run_all_rules(self) -> List[Dict[str, Any]]:
        """Evaluate all configured rules against the DuckDB event store."""
        return self.evaluate_rules()
