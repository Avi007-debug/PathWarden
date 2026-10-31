"""Correlate MITRE ATT&CK tactics to Lockheed Martin 7-stage Cyber Kill Chain."""

from pathlib import Path
from typing import Dict, Optional, Tuple, Any
import yaml

from backend.common.enums import KillChainStage, ConfidenceCategory

_DEFAULT_YAML_PATH = Path(__file__).parent.parent / "config" / "attack_to_kc.yaml"

_FALLBACK_TACTIC_TO_STAGE = {
    "reconnaissance": (KillChainStage.RECONNAISSANCE.value, ConfidenceCategory.STRONG.value, "Direct mapping from Reconnaissance tactic"),
    "resource development": (KillChainStage.WEAPONIZATION.value, ConfidenceCategory.STRONG.value, "Mapped Resource Development to Weaponization"),
    "initial access": (KillChainStage.DELIVERY.value, ConfidenceCategory.STRONG.value, "Mapped Initial Access to Delivery"),
    "execution": (KillChainStage.EXPLOITATION.value, ConfidenceCategory.STRONG.value, "Mapped Execution to Exploitation"),
    "privilege escalation": (KillChainStage.EXPLOITATION.value, ConfidenceCategory.MODERATE.value, "Mapped Privilege Escalation to Exploitation"),
    "persistence": (KillChainStage.INSTALLATION.value, ConfidenceCategory.STRONG.value, "Mapped Persistence to Installation"),
    "defense evasion": (KillChainStage.INSTALLATION.value, ConfidenceCategory.MODERATE.value, "Mapped Defense Evasion to Installation"),
    "credential access": (KillChainStage.ACTIONS_ON_OBJECTIVES.value, ConfidenceCategory.STRONG.value, "Mapped Credential Access to Actions on Objectives"),
    "discovery": (KillChainStage.ACTIONS_ON_OBJECTIVES.value, ConfidenceCategory.STRONG.value, "Mapped Discovery to Actions on Objectives"),
    "lateral movement": (KillChainStage.ACTIONS_ON_OBJECTIVES.value, ConfidenceCategory.STRONG.value, "Mapped Lateral Movement to Actions on Objectives"),
    "collection": (KillChainStage.ACTIONS_ON_OBJECTIVES.value, ConfidenceCategory.STRONG.value, "Mapped Collection to Actions on Objectives"),
    "command and control": (KillChainStage.COMMAND_AND_CONTROL.value, ConfidenceCategory.STRONG.value, "Direct mapping from Command and Control"),
    "exfiltration": (KillChainStage.ACTIONS_ON_OBJECTIVES.value, ConfidenceCategory.STRONG.value, "Mapped Exfiltration to Actions on Objectives"),
    "impact": (KillChainStage.ACTIONS_ON_OBJECTIVES.value, ConfidenceCategory.STRONG.value, "Mapped Impact to Actions on Objectives"),
}


class KillChainMapper:
    """Maps MITRE ATT&CK tactics to Cyber Kill Chain stages."""

    def __init__(self, config_path: Optional[str] = None):
        path = Path(config_path) if config_path else _DEFAULT_YAML_PATH
        self._mapping: Dict[str, Tuple[str, str, str]] = {}
        self._load_config(path)

    def _load_config(self, path: Path) -> None:
        if path.exists():
            try:
                with open(path, "r", encoding="utf-8") as f:
                    cfg = yaml.safe_load(f)
                stages = cfg.get("kill_chain_stages", {})
                for stage_name, info in stages.items():
                    tactics = info.get("tactics", [])
                    for tactic in tactics:
                        self._mapping[tactic.strip().lower()] = (
                            stage_name,
                            ConfidenceCategory.STRONG.value,
                            f"Mapped from tactic '{tactic}' via attack_to_kc.yaml",
                        )
            except Exception:
                pass

        # Populate missing from fallback
        for k, v in _FALLBACK_TACTIC_TO_STAGE.items():
            if k not in self._mapping:
                self._mapping[k] = v

    def map_tactic_to_stage(self, mitre_tactic: Optional[str]) -> Tuple[str, str, str]:
        """
        Maps a MITRE tactic to (kill_chain_stage, kc_confidence, mapping_reason).
        """
        if not mitre_tactic:
            return (
                KillChainStage.ACTIONS_ON_OBJECTIVES.value,
                ConfidenceCategory.INFERRED.value,
                "No tactic provided; defaulted to ACTIONS_ON_OBJECTIVES",
            )
        norm = mitre_tactic.strip().lower().replace("_", " ")
        if norm in self._mapping:
            return self._mapping[norm]

        return (
            KillChainStage.ACTIONS_ON_OBJECTIVES.value,
            ConfidenceCategory.INFERRED.value,
            f"Unrecognized tactic '{mitre_tactic}'; defaulted to ACTIONS_ON_OBJECTIVES",
        )

    def enrich_detection(self, detection: Dict[str, Any]) -> Dict[str, Any]:
        """Enriches detection record in-place with kill chain fields."""
        tactic = detection.get("mitre_tactic")
        stage, conf, reason = self.map_tactic_to_stage(tactic)
        detection["kill_chain_stage"] = stage
        detection["kc_confidence"] = conf
        detection["mapping_reason"] = reason
        return detection
