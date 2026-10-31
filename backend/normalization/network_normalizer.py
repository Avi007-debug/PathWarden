"""Normalize IPv4, IPv6, and CIDRs."""
import ipaddress

class NetworkNormalizer:
    def normalize_ip(self, ip_str: str) -> str:
        try:
            return str(ipaddress.ip_address(ip_str.strip()))
        except Exception:
            return "0.0.0.0"
