"""Orchestrate ingestion pipeline stages with memory throttling."""
from common.logger import get_logger
from common.metrics import get_system_metrics

logger = get_logger("IngestionManager")

class IngestionManager:
    def __init__(self, max_memory_gb: float = 8.0):
        self.max_memory_gb = max_memory_gb
        self.processed_bytes = 0

    def check_memory_budget(self) -> bool:
        metrics = get_system_metrics()
        if metrics.memory_used_gb > self.max_memory_gb:
            logger.warning(f"Memory threshold reached: {metrics.memory_used_gb} GB > {self.max_memory_gb} GB")
            return False
        return True
