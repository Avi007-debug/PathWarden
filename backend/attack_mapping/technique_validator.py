"""Validate MITRE ATT&CK technique IDs against the local enterprise ATT&CK dataset."""

import json
import re
from pathlib import Path
from typing import Dict, Optional, Any

_TECHNIQUE_ID_REGEX = re.compile(r"^T\d{4}(\.\d{3})?$")

_DEFAULT_JSON_PATH = Path(__file__).parent / "attack_data" / "enterprise-attack.json"


class TechniqueValidator:
    """Validates technique IDs and resolves their official metadata."""

    def __init__(self, data_path: Optional[str] = None):
        path = Path(data_path) if data_path else _DEFAULT_JSON_PATH
        self._techniques: Dict[str, Dict[str, Any]] = {}
        self._load_bundle(path)

    def _load_bundle(self, path: Path) -> None:
        if not path.exists():
            return
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            objects = data.get("objects", [])
            for obj in objects:
                tid = obj.get("external_id")
                if tid:
                    self._techniques[tid] = {
                        "external_id": tid,
                        "name": obj.get("name", "Unknown Technique"),
                        "tactic": obj.get("tactic"),
                    }
        except Exception:
            self._techniques = {}

    def is_valid_format(self, technique_id: str) -> bool:
        """Checks if the ID conforms to MITRE syntax Txxxx or Txxxx.yyy."""
        if not technique_id:
            return False
        return bool(_TECHNIQUE_ID_REGEX.match(technique_id.strip()))

    def is_valid(self, technique_id: str) -> bool:
        """True if format is valid and technique exists in local bundle."""
        if not self.is_valid_format(technique_id):
            return False
        return technique_id.strip() in self._techniques

    def get_technique(self, technique_id: str) -> Optional[Dict[str, Any]]:
        """Return dict with external_id, name, and tactic or None."""
        if not technique_id:
            return None
        return self._techniques.get(technique_id.strip())

    def get_technique_name(self, technique_id: str) -> Optional[str]:
        t = self.get_technique(technique_id)
        return t["name"] if t else None

    def get_tactic(self, technique_id: str) -> Optional[str]:
        t = self.get_technique(technique_id)
        return t.get("tactic") if t else None
