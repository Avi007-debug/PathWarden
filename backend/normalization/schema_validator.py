"""Validate normalized records against strict schema."""
class SchemaValidator:
    REQUIRED_FIELDS = ["event_id", "timestamp", "host_name"]

    def validate(self, record: dict) -> bool:
        return all(f in record and record[f] is not None for f in self.REQUIRED_FIELDS)
