"""Resource and processing metrics recorder."""

import psutil
from dataclasses import dataclass

@dataclass
class SystemMetrics:
    memory_used_gb: float
    memory_total_gb: float
    memory_percent: float
    cpu_percent: float

def get_system_metrics() -> SystemMetrics:
    mem = psutil.virtual_memory()
    return SystemMetrics(
        memory_used_gb=round(mem.used / (1024 ** 3), 2),
        memory_total_gb=round(mem.total / (1024 ** 3), 2),
        memory_percent=mem.percent,
        cpu_percent=psutil.cpu_percent(interval=None)
    )
