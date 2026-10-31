"""Adapter for DNS queries."""
class DNSAdapter:
    def adapt(self, record: dict) -> dict:
        return {
            "query_name": record.get("dns", {}).get("question", {}).get("name") or record.get("query"),
            "record_type": record.get("dns", {}).get("question", {}).get("type")
        }
