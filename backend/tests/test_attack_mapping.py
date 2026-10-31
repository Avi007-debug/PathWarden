"""Tests for MITRE ATT&CK and Kill Chain mapping."""

from backend.attack_mapping.technique_validator import TechniqueValidator
from backend.attack_mapping.kill_chain_mapper import KillChainMapper
from backend.attack_mapping.attack_mapper import AttackMapper
from backend.common.enums import KillChainStage


def test_technique_validation():
    tv = TechniqueValidator()
    assert tv.is_valid("T1003.001")
    assert tv.is_valid("T1046")
    assert not tv.is_valid("INVALID")
    assert tv.get_technique_name("T1003.001") == "LSASS Memory"


def test_kill_chain_mapper():
    kcm = KillChainMapper()
    stage, conf, _ = kcm.map_tactic_to_stage("Initial Access")
    assert stage == KillChainStage.DELIVERY.value
    stage2, conf2, _ = kcm.map_tactic_to_stage("Credential Access")
    assert stage2 == KillChainStage.ACTIONS_ON_OBJECTIVES.value


def test_attack_mapper_integration():
    am = AttackMapper()
    rec = {"mitre_technique_id": "T1110.001"}
    am.enrich(rec)
    assert rec["mitre_technique_name"] == "Password Guessing"
    assert rec["mitre_tactic"] == "Credential Access"
    assert rec["kill_chain_stage"] == KillChainStage.ACTIONS_ON_OBJECTIVES.value
