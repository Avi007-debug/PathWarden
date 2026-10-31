"""Network / firewall telemetry adapter.

Adapter Pattern — why two steps (Parser + Adapter)?
    The TextParser extracts raw key-value pairs from the log line text.
    It handles SYNTAX: "what are the fields in this text?"

    The NetworkAdapter maps those raw fields to the canonical schema names.
    It handles SEMANTICS: "what does this field mean in our system?"

    Keeping them separate means:
    - A different firewall vendor just needs a new Adapter, not a new Parser.
    - The Normalizer always receives the same canonical field names regardless
      of source vendor — it doesn't need to know anything about the raw format.

    Example flow:
        TextParser → {"src_ip": "168.168.208.87", "action": "DENY", "dpt": "22"}
        NetworkAdapter → {"src_ip": "168.168.208.87", "action": "block",
                          "dst_port": 22, "event_type": "NETWORK_FLOW",
                          "event_category": "network", "outcome": "failure"}
        EventNormalizer → canonical event record

What this adapter covers:
    - Firewall allow/deny traffic flows
    - Authentication attempts (login bursts, brute force) visible in firewall logs
    - Web application attacks (SQL injection, path traversal, web shell) via HTTP fields
    - C2 beaconing, DNS tunneling, exfiltration patterns (detected at the flow level)
    - DoS/DDoS flood events (SYN flood, HTTP flood, DNS amplification)
"""

from typing import Any, Dict, Optional

from common.enums import ParseStatus


# Action string → canonical outcome mapping
_ACTION_TO_OUTCOME: Dict[str, str] = {
    "allow"   : "SUCCESS",
    "allowed" : "SUCCESS",
    "accept"  : "SUCCESS",
    "permit"  : "SUCCESS",
    "pass"    : "SUCCESS",
    "deny"    : "FAILURE",
    "denied"  : "FAILURE",
    "block"   : "FAILURE",
    "blocked" : "FAILURE",
    "drop"    : "FAILURE",
    "dropped" : "FAILURE",
    "reject"  : "FAILURE",
    "rejected": "FAILURE",
}

# Action string → canonical action (lowercase, normalised)
_ACTION_NORM: Dict[str, str] = {
    "allow" : "allow", "allowed": "allow", "accept": "allow",
    "permit": "allow", "pass"   : "allow",
    "deny"  : "block", "denied" : "block", "block" : "block",
    "blocked":"block", "drop"   : "block", "dropped":"block",
    "reject": "block", "rejected":"block",
}

# Protocol normalisation — uppercase canonical form
_PROTO_NORM: Dict[str, str] = {
    "tcp": "TCP", "udp": "UDP", "icmp": "ICMP",
    "dns": "DNS", "http": "HTTP", "https": "HTTPS",
    "ftp": "FTP", "ssh": "SSH", "smb": "SMB",
    "rdp": "RDP", "telnet": "TELNET", "smtp": "SMTP",
}

# Destination ports commonly associated with specific protocols
_PORT_PROTO_HINT: Dict[int, str] = {
    22: "SSH", 23: "TELNET", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 389: "LDAP",
    443: "HTTPS", 445: "SMB", 3389: "RDP", 8080: "HTTP",
    8443: "HTTPS", 636: "LDAPS", 1433: "MSSQL", 3306: "MYSQL",
    5985: "WINRM", 5986: "WINRM",
}


class NetworkAdapter:
    """Maps TextParser output to canonical firewall/network event fields.

    The adapter is stateless — no instance state is needed. It can safely
    be shared across workers (but each worker creates its own instance anyway).
    """

    def adapt(self, parsed: Dict[str, Any]) -> Dict[str, Any]:
        """Convert TextParser dict to canonical-ready field dict.

        Args:
            parsed: Output of TextParser.parse_record() — raw extracted fields.

        Returns:
            Dict with canonical field names ready for EventNormalizer.normalize().
            All unrecognised fields are preserved in their original form — the
            EventNormalizer will route them into `extra`.
        """
        # ── Timestamps ────────────────────────────────────────────────────────
        event_ts_original = (
            parsed.get("event_ts_original")
            or parsed.get("timestamp")
            or parsed.get("ts")
        )

        # ── Network fields ────────────────────────────────────────────────────
        src_ip   = parsed.get("src_ip")
        dst_ip   = parsed.get("dst_ip")
        src_port = self._to_int(parsed.get("src_port"))
        dst_port = self._to_int(parsed.get("dst_port"))

        # ── Protocol ─────────────────────────────────────────────────────────
        raw_proto = (parsed.get("network_protocol") or parsed.get("proto") or "").upper()
        # Attempt to infer protocol from destination port if not stated
        if not raw_proto and dst_port:
            raw_proto = _PORT_PROTO_HINT.get(dst_port, "")
        network_protocol = raw_proto if raw_proto else None

        # ── Action / Outcome ─────────────────────────────────────────────────
        raw_action = str(parsed.get("action") or "").lower()
        action     = _ACTION_NORM.get(raw_action) or (raw_action or None)
        outcome    = _ACTION_TO_OUTCOME.get(raw_action)  # None if unrecognised

        # FortiGate auth events use action="login" with a separate status field.
        # Override outcome from explicit status when action alone does not tell us.
        if outcome is None:
            raw_status = str(parsed.get("status") or "").lower()
            if raw_status in ("failed", "failure", "denied"):
                outcome = "FAILURE"
            elif raw_status in ("success", "succeeded", "allowed"):
                outcome = "SUCCESS"

        # ── Host and User ─────────────────────────────────────────────────────
        host_name  = parsed.get("host_name") or parsed.get("device") or parsed.get("host")
        user_name  = parsed.get("user_name") or parsed.get("user") or parsed.get("username")
        sensor_id  = parsed.get("sensor_id") or parsed.get("collector") or parsed.get("agent")

        # ── Event classification ──────────────────────────────────────────────
        # Infer event_type from protocol and port combinations
        event_type, event_category = self._classify_event(
            network_protocol, dst_port, parsed
        )

        # ── Source-specific fields (go into extra via normalizer) ─────────────
        # Keep everything the parser gave us that we did not explicitly map above,
        # plus any CEF-specific fields. The EventNormalizer will route them to extra.
        extra_passthrough: Dict[str, Any] = {}
        known_keys = {
            "event_ts_original", "timestamp", "ts",
            "src_ip", "dst_ip", "src_port", "dst_port",
            "network_protocol", "proto", "action", "verdict",
            "host_name", "device", "host", "user_name", "user", "username",
            "sensor_id", "collector", "agent", "parse_status", "raw_line", "status",
        }
        for k, v in parsed.items():
            if k not in known_keys and v is not None:
                extra_passthrough[k] = v

        result: Dict[str, Any] = {
            "event_ts_original"  : event_ts_original,
            "event_ts"           : event_ts_original,    # normalizer will parse it
            "event_category"     : event_category,
            "event_type"         : event_type,
            "action"             : action,
            "outcome"            : outcome,
            "host_name"          : host_name,
            "user_name"          : user_name,
            "sensor_id"          : sensor_id,
            "src_ip"             : src_ip,
            "src_port"           : src_port,
            "dst_ip"             : dst_ip,
            "dst_port"           : dst_port,
            "network_protocol"   : network_protocol,
            "parse_status"       : parsed.get("parse_status", ParseStatus.PARSED.value),
        }

        # Merge extra passthrough fields — normalizer routes them to extra column
        result.update(extra_passthrough)
        return result

    # ── Private helpers ────────────────────────────────────────────────────────

    def _classify_event(
        self,
        protocol : Optional[str],
        dst_port : Optional[int],
        parsed   : Dict[str, Any],
    ):
        """Infer event_type and event_category from network context.

        Returns (event_type, event_category) strings or (None, 'network').
        """
        category = "network"

        # Authentication events visible in firewall logs
        if dst_port in (22, 23, 3389, 445, 5985, 5986):
            return "NETWORK_AUTH_ATTEMPT", "authentication"

        # DNS queries
        if dst_port == 53 or protocol == "DNS":
            return "DNS_QUERY", "network"

        # HTTP/HTTPS web traffic
        if dst_port in (80, 8080, 443, 8443) or protocol in ("HTTP", "HTTPS"):
            return "HTTP_REQUEST", "web"

        # Generic network flow
        if protocol in ("TCP", "UDP", "ICMP"):
            return "NETWORK_FLOW", category

        return None, category

    def _to_int(self, value: Any) -> Optional[int]:
        """Safely convert a value to int, returning None on failure."""
        if value is None:
            return None
        try:
            return int(value)
        except (ValueError, TypeError):
            return None
