"""Validate technique ID format against official MITRE Enterprise ATT&CK matrix."""
import re

class TechniqueValidator:
    REGEX = re.compile(r"^T1\\d{3}(\\.\\d{3})?$")

    def is_valid(self, technique_id: str) -> bool:
        return bool(self.REGEX.match(technique_id.strip()))
