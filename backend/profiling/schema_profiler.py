"""Profile field nullability, data types, and value cardinality."""
from typing import List, Dict, Any
from collections import Counter

class SchemaProfiler:
    def __init__(self):
        self.field_types = {}
        self.field_counts = Counter()
        self.total_records = 0

    def ingest_sample(self, record: Dict[str, Any]):
        self.total_records += 1
        for k, v in record.items():
            self.field_counts[k] += 1
            t = type(v).__name__
            self.field_types.setdefault(k, Counter())[t] += 1

    def get_profile(self) -> Dict[str, Any]:
        return {
            "total_records": self.total_records,
            "fields": {
                k: {
                    "coverage_pct": round((self.field_counts[k] / self.total_records) * 100, 2),
                    "types": dict(self.field_types[k])
                }
                for k in self.field_counts
            }
        }
