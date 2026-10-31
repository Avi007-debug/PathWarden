"""Fallback generic adapter."""
class GenericAdapter:
    def adapt(self, record: dict) -> dict:
        return record
