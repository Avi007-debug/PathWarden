"""Tests for attack mapping."""
from attack_mapping.technique_validator import TechniqueValidator
from attack_mapping.kill_chain_mapper import KillChainMapper

def test_technique_validation():
    tv = TechniqueValidator()
    assert tv.is_valid("T1003.001")
    assert tv.is_valid("T1059")
    assert not tv.is_valid("INVALID")

def test_kill_chain_mapper():
    kcm = KillChainMapper()
    assert kcm.map_tactic_to_kc("INITIAL_ACCESS") == "DELIVERY"
