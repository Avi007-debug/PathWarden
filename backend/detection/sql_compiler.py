"""Compile rule conditions into optimized DuckDB SQL statements."""
class SQLCompiler:
    def compile_condition(self, field: str, op: str, value: Any) -> str:
        if op == "EQUALS":
            return f"{field} = '{value}'"
        elif op == "CONTAINS":
            return f"{field} LIKE '%{value}%'"
        return f"{field} = '{value}'"
