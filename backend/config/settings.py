"""PathWarden central configuration settings."""

import os
from pydantic_settings import BaseSettings
from typing import Optional


def _resolve_data_dir() -> str:
    env_dir = os.environ.get("DATA_DIR") or os.environ.get("PATHWARDEN_DATA_DIR")
    if env_dir and os.path.exists(env_dir):
        return env_dir

    backend_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    repo_root = os.path.abspath(os.path.join(backend_root, ".."))

    candidates = [
        os.path.abspath("./data"),
        os.path.join(repo_root, "data"),
        os.path.abspath("../data"),
        os.path.join(backend_root, "data"),
    ]
    for c in candidates:
        if os.path.exists(c) and (
            os.path.exists(os.path.join(c, "benchmarks"))
            or os.path.exists(os.path.join(c, "incidents"))
            or os.path.exists(os.path.join(c, "events"))
        ):
            return c

    for c in candidates:
        if os.path.exists(c):
            return c

    return "./data"


class Settings(BaseSettings):
    app_name: str = "PathWarden Threat Investigation Engine"
    env: str = "development"
    host: str = "0.0.0.0"
    port: int = 8000
    data_dir: str = _resolve_data_dir()
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

