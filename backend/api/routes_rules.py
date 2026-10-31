"""PathWarden Bonus B-4: Detection Rules Configuration API.

Allows security analysts to inspect, modify, and add detection rules (Sigma/YAML)
directly by editing configuration files without touching any application code.
"""

import os
from pathlib import Path
from typing import Any, Dict, List, Optional
import yaml
from fastapi import APIRouter, HTTPException, Body
from pydantic import BaseModel, Field

from common.logger import get_logger
from detection.rule_validator import RuleValidator

logger = get_logger("API.Rules")

router = APIRouter(tags=["rules"])

_RULES_YAML_PATH = Path(__file__).parent.parent / "config" / "detection_rules.yaml"
_validator = RuleValidator()


class RuleModel(BaseModel):
    rule_id: str = Field(..., description="Unique rule identifier e.g. RULE-T1059-001")
    rule_name: str = Field(..., description="Human-readable rule name")
    rule_version: str = Field(default="1.0.0")
    technique_id: str = Field(..., description="MITRE ATT&CK technique ID e.g. T1059.001")
    technique_name: str = Field(..., description="MITRE ATT&CK technique name")
    severity: str = Field(default="HIGH", description="CRITICAL, HIGH, MEDIUM, LOW")
    tactic: str = Field(..., description="MITRE ATT&CK tactic e.g. Execution")
    description: str = Field(..., description="Rule detection description")
    query: str = Field(..., description="DuckDB SQL detection query")


def _read_rules_from_file() -> List[Dict[str, Any]]:
    if not _RULES_YAML_PATH.exists():
        return []
    with open(_RULES_YAML_PATH, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    return data.get("rules", [])


def _write_rules_to_file(rules: List[Dict[str, Any]]) -> None:
    _RULES_YAML_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(_RULES_YAML_PATH, "w", encoding="utf-8") as f:
        yaml.safe_dump({"rules": rules}, f, sort_keys=False, default_flow_style=False)


@router.get("/rules")
@router.get("/api/rules")
def get_rules() -> Dict[str, Any]:
    """Retrieve all active detection rules loaded from YAML configuration (Bonus B-4)."""
    rules = _read_rules_from_file()
    return {
        "rules_count": len(rules),
        "config_path": str(_RULES_YAML_PATH.name),
        "rules": rules,
    }


@router.get("/rules/{rule_id}")
@router.get("/api/rules/{rule_id}")
def get_rule_by_id(rule_id: str) -> Dict[str, Any]:
    """Retrieve a specific detection rule by ID."""
    rules = _read_rules_from_file()
    match = next((r for r in rules if r.get("rule_id") == rule_id), None)
    if not match:
        raise HTTPException(status_code=404, detail=f"Rule {rule_id} not found in configuration")
    return match


@router.post("/rules")
@router.post("/api/rules")
def create_rule(rule: RuleModel) -> Dict[str, Any]:
    """Add a new detection rule by updating the YAML configuration file (Bonus B-4).
    
    Validates syntax and schema before persisting. No Python code edits required.
    """
    rule_dict = rule.model_dump()
    is_valid, err = _validator.validate_rule(rule_dict)
    if not is_valid:
        raise HTTPException(status_code=400, detail=f"Rule validation failed: {err}")

    rules = _read_rules_from_file()
    for existing in rules:
        if existing.get("rule_id") == rule.rule_id:
            raise HTTPException(status_code=409, detail=f"Rule {rule.rule_id} already exists")

    rules.append(rule_dict)
    try:
        _write_rules_to_file(rules)
        logger.info("Bonus B-4: Successfully added rule %s to %s", rule.rule_id, _RULES_YAML_PATH)
    except Exception as exc:  # noqa: BLE001
        logger.error("Failed to write detection rule config: %s", exc)
        raise HTTPException(status_code=500, detail=f"Failed to persist rule: {exc}")

    return {
        "status": "SUCCESS",
        "message": f"Rule {rule.rule_id} successfully persisted to {_RULES_YAML_PATH.name}",
        "rule": rule_dict,
    }


@router.put("/rules/{rule_id}")
@router.put("/api/rules/{rule_id}")
def update_rule(rule_id: str, rule: RuleModel) -> Dict[str, Any]:
    """Update an existing detection rule in the YAML config file."""
    rule_dict = rule.model_dump()
    rule_dict["rule_id"] = rule_id
    is_valid, err = _validator.validate_rule(rule_dict)
    if not is_valid:
        raise HTTPException(status_code=400, detail=f"Rule validation failed: {err}")

    rules = _read_rules_from_file()
    found = False
    for i, r in enumerate(rules):
        if r.get("rule_id") == rule_id:
            rules[i] = rule_dict
            found = True
            break

    if not found:
        rules.append(rule_dict)

    _write_rules_to_file(rules)
    logger.info("Bonus B-4: Updated rule %s in config file", rule_id)
    return {
        "status": "SUCCESS",
        "message": f"Rule {rule_id} successfully updated in {_RULES_YAML_PATH.name}",
        "rule": rule_dict,
    }


@router.delete("/rules/{rule_id}")
@router.delete("/api/rules/{rule_id}")
def delete_rule(rule_id: str) -> Dict[str, Any]:
    """Remove a detection rule from the YAML config file."""
    rules = _read_rules_from_file()
    updated = [r for r in rules if r.get("rule_id") != rule_id]
    if len(updated) == len(rules):
        raise HTTPException(status_code=404, detail=f"Rule {rule_id} not found in configuration")

    _write_rules_to_file(updated)
    logger.info("Bonus B-4: Deleted rule %s from config file", rule_id)
    return {"status": "SUCCESS", "message": f"Rule {rule_id} removed from configuration"}

