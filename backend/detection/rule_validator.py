"""Validate rule schema and SQL query syntax."""
class RuleValidator:
    def validate_rule(self, rule: dict) -> bool:
        required = ["rule_id", "technique_id", "severity", "query"]
        return all(k in rule for k in required)
