"""Adapter for endpoint EDR telemetries."""
class EndpointAdapter:
    def adapt(self, record: dict) -> dict:
        return {
            "host_name": record.get("host", {}).get("name") or record.get("agent", {}).get("hostname"),
            "process_name": record.get("process", {}).get("name") or record.get("process", {}).get("executable"),
            "pid": record.get("process", {}).get("pid"),
            "command_line": record.get("process", {}).get("command_line")
        }
