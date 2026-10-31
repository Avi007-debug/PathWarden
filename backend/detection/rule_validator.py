"""Validate rule schema and SQL query structure."""

from typing import Dict, Any, List, Tuple


class RuleValidator:
    """Validates detection rule definitions against mandatory contract fields."""

    REQUIRED_FIELDS = ["rule_id", "rule_name", "technique_id", "severity", "query"]

    def validate_rule(self, rule: Dict[str, Any]) -> Tuple[bool, List[str]]:
        """Checks if rule has all required fields and valid types."""
        errors: List[str] = []
        if not isinstance(rule, dict):
            return False, ["Rule is not a dictionary"]

        for f in self.REQUIRED_FIELDS:
            if f not in rule or rule[f] is None:
                errors.append(f"Missing required rule field: {f}")

        # Ensure query is non-empty string
        query = rule.get("query")
        if query is not None and (not isinstance(query, str) or not query.strip()):
            errors.append("Rule query must be a non-empty SQL string")

        return len(errors) == 0, errors
