"""Load detection rules from YAML configurations."""
import yaml

class RuleLoader:
    def load_rules(self, yaml_path: str):
        with open(yaml_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
        return data.get("rules", [])
