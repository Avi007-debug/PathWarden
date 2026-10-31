"""PathWarden central configuration settings."""

from pydantic_settings import BaseSettings
from typing import Optional

class Settings(BaseSettings):
    app_name: str = "PathWarden Threat Investigation Engine"
    env: str = "development"
    host: str = "0.0.0.0"
    port: int = 8000
    data_dir: str = "./data"
    log_dir: str = "./logs"
    max_memory_gb: float = 8.0
    temporal_window_seconds: int = 300
    max_gap_seconds: int = 600
    storage_engine: str = "duckdb"
    log_level: str = "INFO"

    class Config:
        env_prefix = "PATHWARDEN_"
        env_file = ".env"
        extra = "allow"

settings = Settings()

