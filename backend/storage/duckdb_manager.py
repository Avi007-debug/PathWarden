"""In-process DuckDB analytical engine — memory-capped, Parquet-backed.

Why DuckDB over SQLite or Pandas:
    - DuckDB is a columnar analytical engine embedded in-process. No server needed.
    - It reads Parquet files DIRECTLY without loading them into memory first.
    - Query execution uses vectorised operations (SIMD) on columns — extremely fast
      for the aggregations and window functions our detection rules need.
    - The 'max_memory' setting makes DuckDB spill to disk rather than crash
      when intermediate result sets grow large during complex detection queries.

Memory management:
    We set DuckDB's max_memory to 3 GB. Combined with the ingestion pipeline's
    ~200-500 MB working set, total peak RAM stays under our 8 GB budget.

How the events view works:
    After each Parquet batch is written to disk, we refresh the 'events' view
    to include the new file. DuckDB uses a glob pattern:
        SELECT * FROM read_parquet('data/normalized/events_batch_*.parquet')
    This means:
    - No data is loaded into memory upfront.
    - Every query scans only the columns it needs (column pruning).
    - Row group statistics allow DuckDB to skip entire chunks (pushdown filtering).
    - New Parquet files are automatically included after a view refresh.
"""

import os
from typing import Any, Dict, List, Optional

import duckdb


class DuckDBManager:
    """Memory-capped DuckDB instance with Parquet-backed event views.

    Args:
        db_path    : Path for DuckDB's persistent database file. Use ':memory:'
                     for a pure in-memory instance (no persistence between runs).
                     For the ingestion pipeline, ':memory:' is correct because
                     the durable storage is the Parquet files themselves.
        max_memory : DuckDB memory budget string (e.g. '3GB'). When exceeded,
                     DuckDB spills temp data to disk instead of crashing.
        temp_dir   : Directory for DuckDB's spill files. Defaults to OS temp.
    """

    def __init__(
        self,
        db_path   : str = ":memory:",
        max_memory: str = "3GB",
        temp_dir  : Optional[str] = None,
    ):
        self.db_path    = db_path
        self.max_memory = max_memory
        self._con       = duckdb.connect(db_path)

        # Apply memory cap — this is the single most important config setting
        self._con.execute(f"SET max_memory='{max_memory}'")

        # Set temp directory for spill files if specified
        if temp_dir:
            os.makedirs(temp_dir, exist_ok=True)
            self._con.execute(f"SET temp_directory='{temp_dir}'")

        # Enable parallel query execution (uses all available CPU cores)
        self._con.execute("SET threads TO 4")

        self._events_glob: Optional[str] = None   # current Parquet glob pattern

    # ── View management ────────────────────────────────────────────────────────

    def register_events_view(self, glob_pattern: str) -> None:
        """Register (or refresh) the 'events' view over all Parquet batch files.

        This is called:
          - Once after the first Parquet file is written.
          - Again after each subsequent batch to include new files.
          - By the detection engine before running rules.

        The VIEW does not load any data — it is a lazy query template.
        DuckDB resolves the glob and reads files only when a query is executed.

        Args:
            glob_pattern: Glob path e.g. 'backend/data/normalized/events_batch_*.parquet'
        """
        self._events_glob = glob_pattern
        # Use forward slashes — DuckDB on Windows handles both but prefers /
        pattern = glob_pattern.replace("\\", "/")
        self._con.execute(
            f"CREATE OR REPLACE VIEW events AS "
            f"SELECT * FROM read_parquet('{pattern}', hive_partitioning=false)"
        )

    def refresh_events_view(self) -> None:
        """Re-register the events view using the last known glob pattern.

        Call this after writing a new Parquet batch so new records are
        immediately queryable without restarting the DuckDB connection.
        """
        if self._events_glob:
            self.register_events_view(self._events_glob)

    # ── Query execution ────────────────────────────────────────────────────────

    def execute_query(self, query: str, params: Optional[List[Any]] = None) -> List[Dict[str, Any]]:
        """Execute a SQL query and return results as a list of dicts.

        Each dict maps column name → value. Null values in Parquet become
        None in Python — NOT 0, "", or False.

        Args:
            query : DuckDB SQL string. May contain ? placeholders for params.
            params: Optional list of parameter values for safe parameterized queries.
                    Always use params instead of f-strings for user-supplied values
                    to prevent SQL injection.

        Returns:
            List of row dicts. Empty list if query returns no rows.

        Example:
            rows = mgr.execute_query(
                "SELECT event_uid, src_ip FROM events WHERE src_ip = ?",
                params=["168.168.208.87"]
            )
        """
        try:
            if params:
                cursor = self._con.execute(query, params)
            else:
                cursor = self._con.execute(query)

            if cursor.description is None:
                return []

            columns = [desc[0] for desc in cursor.description]
            return [dict(zip(columns, row)) for row in cursor.fetchall()]

        except duckdb.Error as exc:
            raise RuntimeError(
                f"DuckDB query failed.\nQuery: {query[:200]}\nError: {exc}"
            ) from exc

    def execute_scalar(self, query: str, params: Optional[List[Any]] = None) -> Any:
        """Execute a query and return a single scalar value (first col of first row).

        Useful for COUNT(*), MAX(event_ts), etc.
        Returns None if the query returns no rows.
        """
        rows = self.execute_query(query, params)
        if not rows:
            return None
        return next(iter(rows[0].values()))

    # ── Utility ────────────────────────────────────────────────────────────────

    def table_exists(self, table_name: str) -> bool:
        """Check if a table or view with the given name exists."""
        result = self.execute_scalar(
            "SELECT COUNT(*) FROM information_schema.tables WHERE table_name = ?",
            params=[table_name],
        )
        return bool(result and int(result) > 0)

    def get_event_count(self) -> int:
        """Return total number of events currently in the events view."""
        if not self.table_exists("events"):
            return 0
        result = self.execute_scalar("SELECT COUNT(*) FROM events")
        return int(result) if result else 0

    def get_memory_info(self) -> Dict[str, Any]:
        """Return DuckDB's current memory usage statistics."""
        try:
            rows = self.execute_query(
                "SELECT * FROM duckdb_memory() LIMIT 5"
            )
            return {"memory_rows": rows, "max_memory": self.max_memory}
        except Exception:
            return {"max_memory": self.max_memory, "memory_rows": []}

    def close(self) -> None:
        """Close the DuckDB connection and release all resources."""
        self._con.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()
