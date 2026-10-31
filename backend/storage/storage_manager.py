"""Coordinate Parquet persistence and DuckDB table views."""
from storage.parquet_writer import ParquetWriter
from storage.duckdb_manager import DuckDBManager

class StorageManager:
    def __init__(self, base_dir: str = "data/normalized"):
        self.writer = ParquetWriter(base_dir)
        self.duck = DuckDBManager()
