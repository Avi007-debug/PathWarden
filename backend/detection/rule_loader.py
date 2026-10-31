"""Load detection rules from YAML configurations with validation."""

from pathlib import Path
from typing import Dict, List, Optional, Any
import yaml

from backend.detection.rule_validator import RuleValidator

_DEFAULT_RULES_PATH = Path(__file__).parent.parent / "config" / "detection_rules.yaml"


class RuleLoader:
    """Loads and caches detection rules from YAML configuration."""

    def __init__(self, yaml_path: Optional[str] = None, validator: Optional[RuleValidator] = None):
        self._path = Path(yaml_path) if yaml_path else _DEFAULT_RULES_PATH
        self._validator = validator or RuleValidator()
        self._rules: Dict[str, Dict[str, Any]] = {}

    def load_rules(self, yaml_path: Optional[str] = None) -> List[Dict[str, Any]]:
        """Load and validate rules from the target file."""
        path = Path(yaml_path) if yaml_path else self._path
        if not path.exists():
            return []

        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}

        raw_rules = data.get("rules", [])
        valid_rules: List[Dict[str, Any]] = []

        for r in raw_rules:
            is_valid, _ = self._validator.validate_rule(r)
            if is_valid:
                rule_id = r["rule_id"]
                self._rules[rule_id] = r
                valid_rules.append(r)

        return valid_rules

    def get_rule(self, rule_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve a loaded rule by ID."""
        if not self._rules:
            self.load_rules()
        return self._rules.get(rule_id)
