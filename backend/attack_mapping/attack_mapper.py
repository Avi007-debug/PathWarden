"""Coordinate MITRE ATT&CK technique resolution and Cyber Kill Chain mapping."""

from typing import Dict, Any, Optional

from backend.attack_mapping.technique_validator import TechniqueValidator
from backend.attack_mapping.kill_chain_mapper import KillChainMapper


class AttackMapper:
    """Enriches detection events with official MITRE ATT&CK metadata and Kill Chain stage."""

    def __init__(
        self,
        validator: Optional[TechniqueValidator] = None,
        kc_mapper: Optional[KillChainMapper] = None,
    ):
        self.validator = validator or TechniqueValidator()
        self.kc_mapper = kc_mapper or KillChainMapper()

    def enrich(self, detection: Dict[str, Any]) -> Dict[str, Any]:
        """
        Enrich a detection dictionary in-place with:
          - mitre_technique_id
          - mitre_technique_name
          - mitre_tactic
          - kill_chain_stage
          - kc_confidence
          - mapping_reason
        """
        tech_id = detection.get("mitre_technique_id")
        if tech_id:
            tech_info = self.validator.get_technique(tech_id)
            if tech_info:
                if not detection.get("mitre_technique_name"):
                    detection["mitre_technique_name"] = tech_info.get("name")
                if not detection.get("mitre_tactic"):
                    detection["mitre_tactic"] = tech_info.get("tactic")
            else:
                if not detection.get("mitre_technique_name"):
                    detection["mitre_technique_name"] = "Custom / Unlisted Technique"
                if not detection.get("mitre_tactic"):
                    detection["mitre_tactic"] = "Execution"

        # Now enrich with kill chain stage
        self.kc_mapper.enrich_detection(detection)
        return detection
