"""PathWarden FR-4: Entity resolver for canonical identity normalization.

Resolves raw host/user/process identifiers from multiple log sources into a
single canonical entity_id form. Designed for stateless lookup — all state
is maintained in CrossBatchState.
"""

import re
import ipaddress
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Tuple
from common.logger import get_logger

logger = get_logger("EntityResolver")

# Format: host:HOSTNAME_LOWER  |  user:DOMAIN\username  |  proc:HOST:PID:STARTSEC
_HOST_PREFIX = "host"
_USER_PREFIX = "user"
_PROC_PREFIX = "proc"

# Known high-degree hub hostnames (Domain Controllers, NAT GWs) — populated at runtime
_KNOWN_HUB_PATTERNS = re.compile(
    r"^(dc\d*|pdc|bdc|gateway|proxy|nat|fw|firewall|jumpbox|bastion)",
    re.IGNORECASE,
)

# DHCP lease window — IPs within this delta are considered same host
_DHCP_WINDOW_SECONDS = 3600


class EntityResolver:
    """Converts raw log field values into stable canonical entity_id strings.

    Thread-safe for read operations; write operations (DHCP cache) must be
    externally serialised when called from the worker.
    """

    def __init__(self) -> None:
        # ip -> (hostname, lease_start, lease_end)
        self._dhcp_cache: Dict[str, list] = {}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def resolve_host(
        self,
        host_id: Optional[str],
        host_name: Optional[str],
        ip: Optional[str],
        event_ts: Optional[datetime] = None,
    ) -> str:
        """Return canonical host entity_id.

        Priority: host_name > DHCP-resolved from ip > ip literal > host_id.
        """
        name = self._canonicalize_hostname(host_name)
        if name:
            # Try to associate ip→name for future lookups
            if ip and event_ts:
                self._register_dhcp(ip, name, event_ts)
            return f"{_HOST_PREFIX}:{name}"

        if host_id:
            return f"{_HOST_PREFIX}:{host_id.strip().lower()}"

        if ip:
            if event_ts:
                resolved = self._resolve_ip(ip, event_ts)
                if resolved:
                    return f"{_HOST_PREFIX}:{resolved}"
            return f"{_HOST_PREFIX}:ip-{self._sanitize_ip(ip)}"

        return f"{_HOST_PREFIX}:unknown"

    def resolve_user(
        self,
        user_id: Optional[str],
        user_name: Optional[str],
        domain: Optional[str] = None,
    ) -> str:
        """Return canonical user entity_id.

        Format: user:DOMAIN\\username (lowercase, backslash separator).
        Service accounts (starting with svc_ or ending with $) are preserved as-is.
        """
        if not user_name:
            if user_id:
                return f"{_USER_PREFIX}:{user_id.strip().lower()}"
            return f"{_USER_PREFIX}:unknown"

        uname = user_name.strip()

        # Already contains domain separator
        if "\\" in uname:
            dom, usr = uname.split("\\", 1)
            return f"{_USER_PREFIX}:{dom.strip().lower()}\\{usr.strip().lower()}"

        if "@" in uname:
            usr, dom = uname.split("@", 1)
            return f"{_USER_PREFIX}:{dom.strip().lower()}\\{usr.strip().lower()}"

        dom_str = (domain or "").strip().lower()
        if dom_str:
            return f"{_USER_PREFIX}:{dom_str}\\{uname.lower()}"

        return f"{_USER_PREFIX}:{uname.lower()}"

    def resolve_process(
        self,
        host_name: Optional[str],
        process_id: Optional[int],
        start_ts: Optional[datetime],
        process_name: Optional[str] = None,
    ) -> str:
        """Return canonical process entity_id (never PID alone — includes host+time).

        Format: proc:HOST:PID:EPOCH_SECOND (truncated to 10s bucket to tolerate
        minor clock skew between endpoint agent and SIEM ingestion).
        """
        host_part = self._canonicalize_hostname(host_name) or "unknown"
        pid_part = str(process_id) if process_id is not None else "nopid"

        if start_ts is not None:
            # Bucket to 10-second intervals to tolerate minor clock drift
            epoch_bucket = (int(start_ts.timestamp()) // 10) * 10
            ts_part = str(epoch_bucket)
        else:
            ts_part = "nots"

        return f"{_PROC_PREFIX}:{host_part}:{pid_part}:{ts_part}"

    def is_hub_candidate(self, entity_id: str) -> bool:
        """Heuristically flag entities likely to be high-degree hubs."""
        name = entity_id.split(":", 1)[-1]
        return bool(_KNOWN_HUB_PATTERNS.match(name))

    # ------------------------------------------------------------------
    # DHCP helpers
    # ------------------------------------------------------------------

    def register_dhcp_lease(
        self, ip: str, hostname: str, lease_start: datetime, lease_end: Optional[datetime] = None
    ) -> None:
        """Register a DHCP lease mapping for IP→hostname resolution."""
        end = lease_end or (lease_start + timedelta(seconds=_DHCP_WINDOW_SECONDS))
        entry = [self._sanitize_ip(ip), self._canonicalize_hostname(hostname) or hostname, lease_start, end]
        self._dhcp_cache.setdefault(self._sanitize_ip(ip), []).append(entry)

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _canonicalize_hostname(self, raw: Optional[str]) -> Optional[str]:
        if not raw:
            return None
        name = raw.strip().lower()
        # Strip trailing domain suffix (keep NETBIOS-style name)
        # e.g. "DC01.CORP.LOCAL" → "dc01.corp.local"  (keep full FQDN — unique in enterprise)
        name = re.sub(r"\s+", "-", name)  # spaces → hyphens
        return name if name else None

    def _sanitize_ip(self, ip: str) -> str:
        try:
            return str(ipaddress.ip_address(ip.strip()))
        except ValueError:
            return ip.strip().replace(":", "-")

    def _register_dhcp(self, ip: str, hostname: str, ts: datetime) -> None:
        sip = self._sanitize_ip(ip)
        end = ts + timedelta(seconds=_DHCP_WINDOW_SECONDS)
        self._dhcp_cache.setdefault(sip, []).append([sip, hostname, ts, end])

    def _resolve_ip(self, ip: str, event_ts: datetime) -> Optional[str]:
        sip = self._sanitize_ip(ip)
        entries = self._dhcp_cache.get(sip, [])
        for entry in reversed(entries):  # Most recent lease first
            _, hostname, lease_start, lease_end = entry
            if lease_start <= event_ts <= lease_end:
                return hostname
        return None

