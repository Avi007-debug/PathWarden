"""Tests for detection rules."""
from detection.rule_validator import RuleValidator

def test_rule_validator():
    rv = RuleValidator()
    assert rv.validate_rule({"rule_id": "R1", "technique_id": "T1", "severity": "HIGH", "query": "SELECT 1"})
    assert not rv.validate_rule({"rule_id": "R1"})
