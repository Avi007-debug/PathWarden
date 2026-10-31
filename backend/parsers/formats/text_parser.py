"""Multi-pattern firewall / syslog text log parser.

Why multi-pattern instead of one fixed regex:
    Real-world firewall log formats vary widely across vendors (pfSense, Cisco ASA,
    iptables, Palo Alto, generic syslog). The firex-30G dataset is generated to
    simulate real traffic — we cannot assume a single rigid format.

    This parser tries four patterns in order of specificity:
      1. CEF (Common Event Format)            — most structured, try first
      2. Key-Value pairs with timestamp prefix — very common for Linux firewalls
      3. Syslog prefix + key-value body       — BSD/pfSense style
      4. Space-separated columnar format      — simple tab/space delimited fallback

    All regexes are PRECOMPILED at import time, not per-record. Compiling a
    regex takes ~100 microseconds; matching takes ~1 microsecond. For 37 million
    firewall lines that difference is ~1 hour vs ~37 seconds of regex overhead.

Performance notes:
    - Use raw strings (r"...") — avoids double-backslash escaping.
    - Named groups (?P<name>...) let us use match.groupdict() cleanly.
    - Non-capturing groups (?:...) for structure without wasting group slots.
    - Anchor with ^ and $ to avoid partial matches on long lines.
"""

import re
from typing import Any, Dict, Optional

from parsers.base_parser import BaseParser
from common.enums import ParseStatus


# ── Precompiled regex patterns ─────────────────────────────────────────────────
# All compiled once at module import. Never recompile inside parse_record().

# Pattern 1 — CEF (Common Event Format)
# Example: CEF:0|Vendor|Product|1.0|100|Login failed|5|src=1.2.3.4 dst=5.6.7.8 act=deny
_RE_CEF = re.compile(
    r"^(?P<syslog_ts>[\w\s:]+)?\s*"
    r"CEF:(?P<cef_version>\d+)\|"
    r"(?P<vendor>[^|]*)\|(?P<product>[^|]*)\|(?P<product_version>[^|]*)\|"
    r"(?P<event_class_id>[^|]*)\|(?P<name>[^|]*)\|(?P<severity>[^|]*)\|"
    r"(?P<extensions>.*)$"
)

# Pattern 2 — ISO timestamp + key=value pairs (most common synthetic/Linux format)
# Example: 2026-10-28 14:41:50 src=168.168.208.87 spt=54321 dst=10.10.10.1 dpt=22 proto=TCP action=DENY
# The optional hostname group only matches if the next token does NOT look like key=value.
# We use a negative lookahead (?!\w+=) to skip hostname capture when KV pairs follow directly.
_RE_KV_ISO = re.compile(
    r"^(?P<timestamp>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+"
    r"(?P<host>(?!\w+=)\S+\s+)?"           # optional hostname only if NOT a key=value token
    r"(?P<kv_body>.+)$"
)

# Pattern 3 — BSD/syslog prefix + key=value body
# Example: Oct 28 14:41:50 fw01 kernel: src=168.168.208.87 dst=10.10.10.1 proto=TCP dpt=22 action=DROP
_RE_SYSLOG_KV = re.compile(
    r"^(?P<timestamp>(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<process>\S+?):\s+"
    r"(?P<kv_body>.+)$"
)

# Pattern 4 — Space-separated columnar (simple fallback)
# Example: 2026-10-28 14:41:50 DENY TCP 168.168.208.87 54321 10.10.10.1 22 64 SYN
_RE_COLUMNAR = re.compile(
    r"^(?P<timestamp>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})\s+"
    r"(?P<action>\w+)\s+"
    r"(?P<proto>\w+)\s+"
    r"(?P<src_ip>\d{1,3}(?:\.\d{1,3}){3})\s+"
    r"(?P<src_port>\d{1,5})\s+"
    r"(?P<dst_ip>\d{1,3}(?:\.\d{1,3}){3})\s+"
    r"(?P<dst_port>\d{1,5})"
    r"(?:\s+(?P<rest>.*))?$"
)

# KV body extractor — matches key=value or key="quoted value"
_RE_KV_PAIR = re.compile(r'(\w+)=(?:"([^"]*?)"|(\S+))')

# Known KV key synonyms → canonical names
_KV_ALIASES: Dict[str, str] = {
    "src"      : "src_ip",
    "sip"      : "src_ip",
    "srcip"    : "src_ip",
    "sourceip" : "src_ip",
    "s_ip"     : "src_ip",
    "dst"      : "dst_ip",
    "dip"      : "dst_ip",
    "dstip"    : "dst_ip",
    "destip"   : "dst_ip",
    "d_ip"     : "dst_ip",
    "spt"      : "src_port",
    "sport"    : "src_port",
    "srcport"  : "src_port",
    "dpt"      : "dst_port",
    "dport"    : "dst_port",
    "dstport"  : "dst_port",
    "destport" : "dst_port",
    "proto"    : "network_protocol",
    "protocol" : "network_protocol",
    "act"      : "action",
    "action"   : "action",
    "verdict"  : "action",
    "msg"      : "message",
    "reason"   : "message",
    "user"     : "user_name",
    "username" : "user_name",
    "host"     : "host_name",
    "hostname" : "host_name",
    "device"   : "host_name",
}


class TextParser(BaseParser):
    """Multi-pattern text log parser supporting CEF, KV, syslog, and columnar formats.

    Usage:
        parser = TextParser()
        record = parser.parse_record("2026-10-28 14:41:50 src=168.1.1.1 dst=10.0.0.1 dpt=22 action=DENY")
        # Returns: {'timestamp': '2026-10-28 14:41:50', 'src_ip': '168.1.1.1', ...}
    """

    def parse_record(self, raw_data: Any) -> Dict[str, Any]:
        """Parse one raw text log line into a structured dict.

        Tries patterns in order: CEF → KV-ISO → Syslog-KV → Columnar → Raw fallback.

        Args:
            raw_data: A single log line (str) or bytes.

        Returns:
            Structured dict with extracted fields + parse_status.
            On failure, returns {'raw_line': ..., 'parse_status': 'PARTIAL'}.
        """
        line = raw_data.decode("utf-8", errors="replace") if isinstance(raw_data, bytes) else str(raw_data)
        line = line.strip()

        if not line:
            return {"parse_status": ParseStatus.MALFORMED.value, "raw_line": line}

        # ── Try Pattern 1: CEF ────────────────────────────────────────────────
        m = _RE_CEF.match(line)
        if m:
            return self._parse_cef(m, line)

        # ── Try Pattern 2: ISO timestamp + KV pairs ───────────────────────────
        m = _RE_KV_ISO.match(line)
        if m:
            kv_body = m.group("kv_body") or ""
            kv      = self._extract_kv(kv_body)
            if kv:
                result = {"event_ts_original": m.group("timestamp"), "parse_status": ParseStatus.PARSED.value}
                result.update(kv)
                return result

        # ── Try Pattern 3: BSD syslog prefix + KV body ───────────────────────
        m = _RE_SYSLOG_KV.match(line)
        if m:
            kv_body = m.group("kv_body") or ""
            kv      = self._extract_kv(kv_body)
            result  = {
                "event_ts_original": m.group("timestamp"),
                "host_name"        : m.group("host"),
                "process_name"     : m.group("process"),
                "parse_status"     : ParseStatus.PARSED.value if kv else ParseStatus.PARTIAL.value,
            }
            result.update(kv)
            return result

        # ── Try Pattern 4: Space-separated columnar ───────────────────────────
        m = _RE_COLUMNAR.match(line)
        if m:
            return {
                "event_ts_original": m.group("timestamp"),
                "action"           : m.group("action"),
                "network_protocol" : m.group("proto"),
                "src_ip"           : m.group("src_ip"),
                "src_port"         : m.group("src_port"),
                "dst_ip"           : m.group("dst_ip"),
                "dst_port"         : m.group("dst_port"),
                "parse_status"     : ParseStatus.PARSED.value,
            }

        # ── Fallback: store raw line for quarantine ───────────────────────────
        # We do NOT raise an exception — malformed lines are counted and stored
        # in the quarantine directory, never silently dropped.
        return {
            "raw_line"    : line,
            "parse_status": ParseStatus.PARTIAL.value,
        }

    # ── Private helpers ────────────────────────────────────────────────────────

    def _parse_cef(self, match: re.Match, raw_line: str) -> Dict[str, Any]:
        """Extract fields from a CEF-format log line."""
        extensions = match.group("extensions") or ""
        kv = self._extract_kv(extensions)
        result = {
            "event_ts_original": (match.group("syslog_ts") or "").strip() or None,
            "event_category"   : match.group("name"),
            "cef_vendor"       : match.group("vendor"),
            "cef_product"      : match.group("product"),
            "cef_event_class"  : match.group("event_class_id"),
            "parse_status"     : ParseStatus.PARSED.value,
        }
        result.update(kv)
        return result

    def _extract_kv(self, body: str) -> Dict[str, Any]:
        """Extract key=value pairs from a string, normalising key names.

        Handles:
            key=value           (unquoted)
            key="quoted value"  (quoted, may contain spaces)

        Returns canonical field names using _KV_ALIASES lookup.
        Unknown keys are returned as-is (they go into `extra` via the adapter).
        """
        result: Dict[str, Any] = {}
        for match in _RE_KV_PAIR.finditer(body):
            raw_key = match.group(1).lower()
            value   = match.group(2) if match.group(2) is not None else match.group(3)
            canon   = _KV_ALIASES.get(raw_key, raw_key)
            result[canon] = value
        return result
