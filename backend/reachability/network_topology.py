"""PathWarden FR-6: Network topology model for reachability analysis.

Builds a routable subnet graph from observed src_ip/dst_ip connection events
stored in Parquet.  When firewall policy data is absent, reachability is
flagged NETWORK_REACHABLE with appropriate caveat.

All queries run through DuckDB over Parquet — no full-dataset Python lists.
"""

from __future__ import annotations

import ipaddress
import os
import glob
from typing import Dict, List, Optional, Set, Tuple

import duckdb

from common.logger import get_logger

logger = get_logger("NetworkTopology")


class NetworkLink:
    """Represents an observed or inferred network link between two hosts."""
    __slots__ = ("src_host", "dst_host", "dst_ip", "confirmed", "protocol", "evidence_uid")

    def __init__(
        self,
        src_host: str,
        dst_host: str,
        dst_ip: str = "",
        confirmed: bool = False,
        protocol: str = "",
        evidence_uid: str = "",
    ) -> None:
        self.src_host = src_host
        self.dst_host = dst_host
        self.dst_ip = dst_ip
        self.confirmed = confirmed
        self.protocol = protocol
        self.evidence_uid = evidence_uid


class NetworkTopology:
    """Subnet/routing model derived from observed connection events in Parquet."""

    def __init__(self, data_dir: str) -> None:
        self.data_dir = data_dir
        # host → set of (dst_host, confirmed, evidence_uid)
        self._adjacency: Dict[str, List[NetworkLink]] = {}
        self._host_subnets: Dict[str, str] = {}   # host → subnet CIDR
        self._firewall_data_present: bool = False
        self._built: bool = False

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def build(self, con: Optional[duckdb.DuckDBPyConnection] = None) -> None:
        """Build topology from Parquet events. Accepts existing DuckDB connection."""
        owns_con = con is None
        if owns_con:
            con = duckdb.connect(":memory:")
        try:
            self._register_events_view(con)
            self._extract_links(con)
            self._extract_subnets()
            self._built = True
            logger.info(
                "NetworkTopology built: %d hosts, firewall_data=%s",
                len(self._adjacency), self._firewall_data_present
            )
        finally:
            if owns_con:
                con.close()

    def get_reachable_hosts(
        self, from_host: str
    ) -> List[Tuple[str, bool, str]]:
        """Return list of (dst_host, confirmed, evidence_uid) reachable from from_host."""
        if not self._built:
            logger.warning("NetworkTopology.build() not called — returning empty")
            return []
        return [
            (link.dst_host, link.confirmed, link.evidence_uid)
            for link in self._adjacency.get(from_host, [])
        ]

    def all_hosts(self) -> Set[str]:
        return set(self._adjacency.keys())

    def has_firewall_data(self) -> bool:
        return self._firewall_data_present

    def get_subnet(self, host: str) -> Optional[str]:
        return self._host_subnets.get(host)

    # ------------------------------------------------------------------
    # Private
    # ------------------------------------------------------------------

    def _register_events_view(self, con: duckdb.DuckDBPyConnection) -> None:
        events_glob = os.path.join(self.data_dir, "events", "*.parquet").replace("\\", "/")
        if glob.glob(os.path.join(self.data_dir, "events", "*.parquet")):
            con.execute(f"CREATE OR REPLACE VIEW net_events AS SELECT * FROM read_parquet('{events_glob}')")
        else:
            con.execute("""
                CREATE OR REPLACE VIEW net_events AS
                SELECT ''::VARCHAR AS host_name, ''::VARCHAR AS dst_ip,
                       ''::VARCHAR AS src_ip, ''::VARCHAR AS protocol,
                       ''::VARCHAR AS event_uid, ''::VARCHAR AS event_type
                WHERE 1=0
            """)

    def _extract_links(self, con: duckdb.DuckDBPyConnection) -> None:
        """Populate adjacency from observed connection events."""
        try:
            rows = con.execute("""
                SELECT
                    host_name,
                    dst_ip,
                    COALESCE(network_protocol, '') AS protocol,
                    event_uid,
                    CASE WHEN event_type IN ('network_accept','authentication_success') THEN TRUE
                         ELSE FALSE END AS confirmed
                FROM net_events
                WHERE dst_ip IS NOT NULL AND dst_ip != ''
                  AND host_name IS NOT NULL AND host_name != ''
                GROUP BY host_name, dst_ip, network_protocol, event_uid, confirmed
            """).fetchall()
        except Exception as exc:  # noqa: BLE001
            logger.warning("NetworkTopology link extraction failed: %s", exc)
            return

        for host, dst_ip, protocol, ev_uid, confirmed in rows:
            link = NetworkLink(
                src_host=host,
                dst_host=dst_ip,   # dst_host starts as IP; resolved later if possible
                dst_ip=dst_ip,
                confirmed=bool(confirmed),
                protocol=protocol or "",
                evidence_uid=ev_uid or "",
            )
            self._adjacency.setdefault(host, []).append(link)

    def _extract_subnets(self) -> None:
        """Derive /24 subnet membership from observed IPs."""
        all_ips: Set[str] = set()
        for links in self._adjacency.values():
            for link in links:
                all_ips.add(link.dst_ip)

        for ip_str in all_ips:
            try:
                ip = ipaddress.ip_address(ip_str)
                network = ipaddress.ip_network(f"{ip}/24", strict=False)
                self._host_subnets[ip_str] = str(network)
            except ValueError:
                pass
