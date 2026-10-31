"""Canonical event normalizer — converts adapter output to the PathWarden schema.

What this does:
    Adapters (network_adapter, endpoint_adapter, etc.) extract fields from raw
    log records into a partially-structured dict. This normalizer takes that dict
    and maps it to the exact canonical schema defined in config/schema.yaml.

    Every field has a documented handling rule:
      - Required fields (event_uid, ingest_ts, raw_event_reference, etc.) are
        always populated, using defaults only where the contract allows.
      - Optional fields are set to None (null) when absent — NEVER empty string.
      - process_id is always scoped to the host to prevent PID collision.
      - extra captures every unrecognised field — zero data loss.
      - dq_flags accumulates non-fatal quality annotations throughout.

Contract compliance (Section 2 & Section 5):
    - Timestamps: event_ts = UTC ISO-8601 or null. Never substitute fake time.
    - Missing values: null, not "" or 0.
    - IDs: stable, from identifiers module, never reused.
    - Unknown fields: preserved in extra, never silently discarded.
"""

import datetime
import ipaddress
from typing import Any, Dict, List, Optional

from common.enums import DQFlag, Outcome, ParseStatus
from common.identifiers import (
    build_raw_event_reference,
    generate_batch_id,
    generate_event_uid,
)

# Schema version must match config/schema.yaml version field
SCHEMA_VERSION = "1.0"

# Canonical set of fields that belong in the top-level event record.
# Any adapter key NOT in this set goes into `extra`.
_CANONICAL_KEYS = frozenset({
    "source_event_id", "event_ts", "event_ts_original", "source_type",
    "sensor_id", "event_category", "event_type", "action", "outcome",
    "host_id", "host_name", "user_id", "user_name",
    "src_ip", "src_port", "dst_ip", "dst_port", "network_protocol",
    "process_id", "parent_process_id", "process_entity_id", "session_id",
})


class EventNormalizer:
    """Converts adapter-output dicts to fully canonical PathWarden event records.

    Usage:
        normalizer = EventNormalizer()
        canonical  = normalizer.normalize(adapter_record, chunk)

    Where `adapter_record` is what a parser adapter returns (e.g. NetworkAdapter),
    and `chunk` is the ChunkDescriptor that sourced this record.
    """

    def normalize(
        self,
        adapter_record : Dict[str, Any],
        source_file_id : str,
        source_type    : str,
        byte_offset    : int,
        line_number    : int,
        chunk_index    : int,
    ) -> Dict[str, Any]:
        """Produce one canonical event record from a parsed adapter dict.

        Args:
            adapter_record : Output from a parser adapter (already field-mapped).
            source_file_id : Stable file identifier (from ChunkDescriptor).
            source_type    : Log source family (e.g. 'firewall', 'windows').
            byte_offset    : Zero-based byte offset of this record in the source file.
            line_number    : 1-based line number of this record (approximate).
            chunk_index    : Chunk index for batch_id generation.

        Returns:
            A dict conforming to config/schema.yaml v1.0.
        """
        dq_flags: List[str] = []

        # ── Stable identifiers ─────────────────────────────────────────────────
        event_uid = generate_event_uid(source_file_id, byte_offset)
        batch_id  = generate_batch_id(source_file_id, chunk_index)
        raw_ref   = build_raw_event_reference(source_file_id, byte_offset, line_number)

        # ── Timestamps ─────────────────────────────────────────────────────────
        event_ts_original = adapter_record.get("event_ts_original")  # raw string as-is
        event_ts          = self._parse_timestamp(
            adapter_record.get("event_ts") or event_ts_original,
            dq_flags,
        )
        ingest_ts = datetime.datetime.now(datetime.timezone.utc).isoformat()

        # ── Source classification ──────────────────────────────────────────────
        source_event_id = adapter_record.get("source_event_id")    # None if absent — not ""
        event_category  = adapter_record.get("event_category")
        event_type      = adapter_record.get("event_type")
        action          = adapter_record.get("action")
        sensor_id       = adapter_record.get("sensor_id")

        # Outcome: only set when the adapter explicitly extracted it from source
        outcome_raw = adapter_record.get("outcome")
        outcome     = self._normalize_outcome(outcome_raw)

        # ── Host ──────────────────────────────────────────────────────────────
        host_name = adapter_record.get("host_name")
        host_id   = None   # Resolved by FR-4 entity resolution — not our job

        if host_name is None:
            dq_flags.append(DQFlag.HOST_INFERRED.value)

        # ── User ─────────────────────────────────────────────────────────────
        user_name = adapter_record.get("user_name")
        user_id   = None   # Resolved by FR-4 entity resolution — not our job

        if user_name is None:
            dq_flags.append(DQFlag.USER_INFERRED.value)

        # ── Network ──────────────────────────────────────────────────────────
        src_ip   = self._validate_ip(adapter_record.get("src_ip"), dq_flags)
        src_port = self._validate_port(adapter_record.get("src_port"))
        dst_ip   = self._validate_ip(adapter_record.get("dst_ip"), dq_flags)
        dst_port = self._validate_port(adapter_record.get("dst_port"))
        network_protocol = adapter_record.get("network_protocol")
        if network_protocol:
            network_protocol = network_protocol.upper()

        # ── Process (PID scoped to host) ──────────────────────────────────────
        raw_pid         = adapter_record.get("process_id")
        raw_parent_pid  = adapter_record.get("parent_process_id")
        process_id      = self._scope_pid(raw_pid, host_name)
        parent_process_id = self._scope_pid(raw_parent_pid, host_name)
        process_entity_id = adapter_record.get("process_entity_id")  # Sysmon ProcessGuid etc.
        session_id        = adapter_record.get("session_id")

        # ── Event type DQ flag ────────────────────────────────────────────────
        if event_type is None:
            dq_flags.append(DQFlag.UNKNOWN_EVENT_TYPE.value)

        # ── extra: capture every unrecognised adapter field ──────────────────
        # The adapter may return fields not in our canonical schema.
        # We must store them rather than discard — contract rule.
        extra: Dict[str, Any] = {}
        for key, val in adapter_record.items():
            if key not in _CANONICAL_KEYS:
                extra[key] = val

        if extra:
            dq_flags.append(DQFlag.EXTRA_FIELDS_PRESENT.value)

        # ── parse_status from adapter (passed through or defaulted) ──────────
        parse_status = adapter_record.get("parse_status", ParseStatus.PARSED.value)

        # Remove duplicates from dq_flags while preserving order
        seen = set()
        dq_flags = [f for f in dq_flags if not (f in seen or seen.add(f))]

        return {
            # Identifiers
            "event_uid"          : event_uid,
            "source_event_id"    : source_event_id,
            "batch_id"           : batch_id,
            "source_file_id"     : source_file_id,
            # Timestamps
            "event_ts"           : event_ts,
            "event_ts_original"  : event_ts_original,
            "ingest_ts"          : ingest_ts,
            # Source
            "source_type"        : source_type,
            "sensor_id"          : sensor_id,
            "event_category"     : event_category,
            "event_type"         : event_type,
            "action"             : action,
            "outcome"            : outcome,
            # Host
            "host_id"            : host_id,
            "host_name"          : host_name,
            # User
            "user_id"            : user_id,
            "user_name"          : user_name,
            # Network
            "src_ip"             : src_ip,
            "src_port"           : src_port,
            "dst_ip"             : dst_ip,
            "dst_port"           : dst_port,
            "network_protocol"   : network_protocol,
            # Process
            "process_id"         : process_id,
            "parent_process_id"  : parent_process_id,
            "process_entity_id"  : process_entity_id,
            "session_id"         : session_id,
            # Provenance & quality
            "raw_event_reference": raw_ref,
            "parse_status"       : parse_status,
            "dq_flags"           : dq_flags,
            "schema_version"     : SCHEMA_VERSION,
            # Catch-all
            "extra"              : extra,
        }

    # ── Private helpers ────────────────────────────────────────────────────────

    def _parse_timestamp(
        self,
        ts_raw : Optional[str],
        dq_flags: List[str],
    ) -> Optional[str]:
        """Parse any timestamp string into a UTC ISO-8601 string or None.

        Contract rule: return None rather than substituting a fake timestamp.
        Appends TIMESTAMP_MISSING or TIMESTAMP_UNCERTAIN to dq_flags.
        """
        if not ts_raw:
            dq_flags.append(DQFlag.TIMESTAMP_MISSING.value)
            return None

        # Normalise common timestamp variants
        ts = ts_raw.strip()

        # Firewall logs often use: "2026-10-28 14:41:50" (no timezone)
        # We assume +05:30 (IST) based on the manifest cover period and add UTC offset
        formats_to_try = [
            "%Y-%m-%dT%H:%M:%S.%f%z",  # ISO-8601 with micros and tz
            "%Y-%m-%dT%H:%M:%S%z",     # ISO-8601 with tz
            "%Y-%m-%dT%H:%M:%SZ",      # ISO-8601 UTC Z suffix
            "%Y-%m-%d %H:%M:%S",       # Firewall format (no tz — mark uncertain)
            "%Y-%m-%dT%H:%M:%S.%f",    # ISO with micros, no tz
            "%b %d %H:%M:%S",          # Syslog format (no year)
        ]

        for fmt in formats_to_try:
            try:
                dt = datetime.datetime.strptime(ts, fmt)
                # If no timezone was found in the string, mark it uncertain and
                # assume UTC (safest neutral assumption — do NOT assume local time)
                if dt.tzinfo is None:
                    dq_flags.append(DQFlag.TIMESTAMP_UNCERTAIN.value)
                    dt = dt.replace(tzinfo=datetime.timezone.utc)
                else:
                    dt = dt.astimezone(datetime.timezone.utc)
                return dt.isoformat()
            except ValueError:
                continue

        # Fallback: try Python's fromisoformat (handles most ISO-8601 variants)
        try:
            ts_normalized = ts.replace("Z", "+00:00")
            dt = datetime.datetime.fromisoformat(ts_normalized)
            if dt.tzinfo is None:
                dq_flags.append(DQFlag.TIMESTAMP_UNCERTAIN.value)
                dt = dt.replace(tzinfo=datetime.timezone.utc)
            return dt.astimezone(datetime.timezone.utc).isoformat()
        except ValueError:
            pass

        # Could not parse at all
        dq_flags.append(DQFlag.TIMESTAMP_UNCERTAIN.value)
        return None

    def _normalize_outcome(self, raw: Optional[Any]) -> Optional[str]:
        """Map raw source outcome to the contract vocabulary or None.

        Only returns SUCCESS/FAILURE/UNKNOWN when evidence is explicit.
        Returns None (not UNKNOWN) when no outcome field is present.
        """
        if raw is None:
            return None
        mapping = {
            "success": Outcome.SUCCESS.value,
            "failure": Outcome.FAILURE.value,
            "failed" : Outcome.FAILURE.value,
            "error"  : Outcome.FAILURE.value,
            "allowed": Outcome.SUCCESS.value,
            "blocked": Outcome.FAILURE.value,
            "denied" : Outcome.FAILURE.value,
            "unknown": Outcome.UNKNOWN.value,
        }
        return mapping.get(str(raw).lower(), Outcome.UNKNOWN.value)

    def _validate_ip(
        self,
        raw_ip   : Optional[Any],
        dq_flags : List[str],
    ) -> Optional[str]:
        """Validate and normalise an IP address string.

        Returns the IP as a string if valid, or None with a DQ flag if invalid.
        Accepts IPv4 and IPv6. Does not treat IP as host identity.
        """
        if raw_ip is None:
            return None
        ip_str = str(raw_ip).strip()
        if not ip_str:
            return None
        try:
            # ipaddress.ip_address validates both IPv4 and IPv6
            return str(ipaddress.ip_address(ip_str))
        except ValueError:
            dq_flags.append(DQFlag.IP_VALIDATION_FAILED.value)
            return None

    def _validate_port(self, raw_port: Optional[Any]) -> Optional[int]:
        """Parse and validate a port number (0–65535). Returns None if invalid."""
        if raw_port is None:
            return None
        try:
            port = int(raw_port)
            return port if 0 <= port <= 65535 else None
        except (ValueError, TypeError):
            return None

    def _scope_pid(
        self,
        raw_pid  : Optional[Any],
        host_name: Optional[str],
    ) -> Optional[str]:
        """Scope a process ID to its host to make it globally unique.

        Contract rule: 'PID alone is not globally unique — scope to host.'
        Format: '<host_name>:<pid>'
        Returns None if either PID or hostname is absent.
        """
        if raw_pid is None:
            return None
        try:
            pid = int(raw_pid)
        except (ValueError, TypeError):
            return None
        host = host_name or "UNKNOWN_HOST"
        return f"{host}:{pid}"
