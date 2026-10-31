"""Tests for detection rules and engine."""

from backend.detection.rule_validator import RuleValidator
from backend.detection.rule_loader import RuleLoader
from backend.detection.sql_compiler import SQLCompiler


def test_rule_validation():
    v = RuleValidator()
    assert v.validate_rule({
        "rule_id": "R1",
        "rule_name": "Test",
        "technique_id": "T1046",
        "severity": "HIGH",
        "query": "SELECT * FROM events",
    })[0]
    assert not v.validate_rule({"rule_id": "R2"})[0]


def test_rule_loader():
    loader = RuleLoader()
    rules = loader.load_rules()
    assert len(rules) >= 15
    assert loader.get_rule("RULE-T1110-001") is not None


def test_sql_compiler():
    compiler = SQLCompiler()
    rule = {"rule_id": "R1", "query": "SELECT * FROM events WHERE fail > {{limit}}"}
    sql = compiler.compile_rule(rule, params={"limit": 5})
    assert "fail > 5" in sql
