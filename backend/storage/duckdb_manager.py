"""In-process DuckDB analytical query engine."""
import duckdb
from typing import List, Dict, Any

class DuckDBManager:
    def __init__(self, db_path: str = ":memory:"):
        self.con = duckdb.connect(db_path)

    def execute_query(self, query: str) -> List[Dict[str, Any]]:
        cursor = self.con.execute(query)
        columns = [desc[0] for desc in cursor.description] if cursor.description else []
        return [dict(zip(columns, row)) for row in cursor.fetchall()]

    def register_parquet(self, glob_pattern: str, table_name: str = "events"):
        self.con.execute(f"CREATE OR REPLACE VIEW {table_name} AS SELECT * FROM read_parquet('{glob_pattern}')")
