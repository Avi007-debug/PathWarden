"""Compile rule definitions and parameters into executable DuckDB SQL statements."""

from typing import Dict, Any, Optional
import re


class SQLCompiler:
    """Compiles rule templates and conditions into executable DuckDB SQL."""

    def compile_rule(
        self,
        rule: Dict[str, Any],
        table_name: str = "events",
        params: Optional[Dict[str, Any]] = None,
    ) -> str:
        """
        Compiles the query from a rule dictionary, substituting template placeholders
        and ensuring target table references are aligned.
        """
        raw_query = rule.get("query", "").strip()
        if not raw_query:
            raise ValueError(f"Rule {rule.get('rule_id')} has no query defined")

        # Merge rule-level parameters if any
        substitutions = dict(rule.get("params", {}))
        if params:
            substitutions.update(params)

        compiled = raw_query
        # Replace {{param}} syntax
        for key, val in substitutions.items():
            pattern = re.compile(rf"\{{\{{\s*{re.escape(key)}\s*\}}\}}")
            compiled = pattern.sub(str(val), compiled)

        # Replace default table name if different
        if table_name != "events":
            compiled = re.sub(r"\bFROM\s+events\b", f"FROM {table_name}", compiled, flags=re.IGNORECASE)

        return compiled

    def compile_condition(self, field: str, op: str, value: Any) -> str:
        """Helper for building single column conditions."""
        op_upper = op.upper().strip()
        if op_upper in ("EQUALS", "="):
            if isinstance(value, (int, float)):
                return f"{field} = {value}"
            return f"{field} = '{value}'"
        elif op_upper in ("CONTAINS", "LIKE"):
            return f"{field} LIKE '%{value}%'"
        elif op_upper in ("IN",):
            if isinstance(value, (list, tuple)):
                items = ", ".join(f"'{v}'" if isinstance(v, str) else str(v) for v in value)
                return f"{field} IN ({items})"
        elif op_upper in (">=", "<=", ">", "<", "!="):
            return f"{field} {op_upper} {value}"

        return f"{field} = '{value}'"
