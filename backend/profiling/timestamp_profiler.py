"""Analyze timestamp consistency and temporal skew."""
from datetime import datetime
from typing import List, Optional

class TimestampProfiler:
    def __init__(self):
        self.min_time: Optional[datetime] = None
        self.max_time: Optional[datetime] = None
        self.count = 0

    def record_timestamp(self, dt: datetime):
        self.count += 1
        if self.min_time is None or dt < self.min_time:
            self.min_time = dt
        if self.max_time is None or dt > self.max_time:
            self.max_time = dt

    def get_summary(self):
        span = (self.max_time - self.min_time).total_seconds() if self.min_time and self.max_time else 0
        return {
            "record_count": self.count,
            "earliest": self.min_time.isoformat() if self.min_time else None,
            "latest": self.max_time.isoformat() if self.max_time else None,
            "duration_seconds": span
        }
