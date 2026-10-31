"""Adapter for network NetFlow and firewall records."""
class NetworkAdapter:
    def adapt(self, record: dict) -> dict:
        return {
            "src_ip": record.get("source", {}).get("ip") or record.get("src_ip"),
            "dest_ip": record.get("destination", {}).get("ip") or record.get("dest_ip"),
            "dest_port": record.get("destination", {}).get("port") or record.get("dest_port")
        }
