"""Reconciliation engine reporting intake, drops, and validation percentages."""
class ReconciliationEngine:
    def __init__(self):
        self.total_received = 0
        self.valid_records = 0
        self.dropped_records = 0

    def record_status(self, is_valid: bool):
        self.total_received += 1
        if is_valid:
            self.valid_records += 1
        else:
            self.dropped_records += 1

    def get_summary(self):
        pct = (self.valid_records / self.total_received * 100) if self.total_received else 100.0
        return {
            "total_received": self.total_received,
            "valid_records": self.valid_records,
            "dropped_records": self.dropped_records,
            "quality_percentage": round(pct, 2)
        }
