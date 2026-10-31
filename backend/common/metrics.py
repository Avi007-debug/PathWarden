"""Resource and processing metrics recorder."""

import os
import platform
import psutil
from dataclasses import dataclass, asdict
from typing import Dict, Any


@dataclass
class SystemMetrics:
    memory_used_gb: float
    memory_total_gb: float
    memory_percent: float
    cpu_percent: float
    cpu_count: int
    memory_process_mb: float
    platform_name: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def get_system_metrics() -> SystemMetrics:
    mem = psutil.virtual_memory()
    proc = psutil.Process(os.getpid())
    proc_mb = round(proc.memory_info().rss / (1024 * 1024), 1)

    return SystemMetrics(
        memory_used_gb=round(mem.used / (1024 ** 3), 2),
        memory_total_gb=round(mem.total / (1024 ** 3), 2),
        memory_percent=round(mem.percent, 1),
        cpu_percent=round(psutil.cpu_percent(interval=None), 1),
        cpu_count=os.cpu_count() or 4,
        memory_process_mb=proc_mb,
        platform_name=f"{platform.system()} {platform.machine()}",
    )
