"""PathWarden FR-6: BFS-based reachability engine.

Performs bounded BFS from compromised hosts/accounts to discover:
  - OBSERVED_SESSION: confirmed auth/connection in logs
  - NETWORK_REACHABLE: routable target, no session observed
  - PRIVILEGE_RELATIONSHIP: user has creds/group membership, no logon occurred

Strict semantics enforced:
  - POTENTIAL is NEVER labelled OBSERVED
  - NETWORK_REACHABLE requires routable dst_ip match only
  - BFS max_depth=2, max_results=50, timeout_sec=2.0
  - Visited set prevents cycles
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Set

from common.enums import EvidenceStatus
from common.logger import get_logger
from .network_topology import NetworkTopology
from .privilege_graph import PrivilegeGraph

logger = get_logger("ReachabilityEngine")

_MAX_DEPTH = 2
_MAX_RESULTS = 50
_TIMEOUT_SEC = 2.0


@dataclass
class ReachabilityItem:
    """Matches the frontend ReachabilityAsset TypeScript type."""
    asset_id: str
    asset_name: str
    asset_type: str
    zone: str
    reachability_status: str          # OBSERVED | NETWORK_REACHABLE | POTENTIAL
    observed_path_steps: int
    potential_path_steps: int
    critical_data_stored: bool
    traversal_evidence: Optional[str] = None
    evidence_uid: Optional[str] = None
    hop_depth: int = 0
    caveat: Optional[str] = None


class ReachabilityEngine:
    """BFS reachability analysis from a set of compromised seed entities."""

    def __init__(
        self,
        topology: NetworkTopology,
        privilege_graph: PrivilegeGraph,
    ) -> None:
        self._topology = topology
        self._privilege_graph = privilege_graph

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def analyze(
        self,
        compromised_hosts: List[str],
        compromised_users: List[str],
        known_asset_types: Optional[Dict[str, str]] = None,
        known_zones: Optional[Dict[str, str]] = None,
        critical_assets: Optional[Set[str]] = None,
    ) -> List[ReachabilityItem]:
        """Run BFS from all compromised seeds; return bounded ReachabilityItem list.

        Args:
            compromised_hosts: Canonical host entity_ids already compromised.
            compromised_users: Canonical user entity_ids already compromised.
            known_asset_types: Optional dict of host → asset_type string.
            known_zones: Optional dict of host → zone string.
            critical_assets: Set of host names storing critical data.
        """
        asset_types = known_asset_types or {}
        zones = known_zones or {}
        crit = critical_assets or set()
        results: List[ReachabilityItem] = []
        visited: Set[str] = set(compromised_hosts)
        deadline = time.monotonic() + _TIMEOUT_SEC

        # BFS queue: (host, depth, path_length, evidence_uid, status_so_far)
        queue: list = [
            (h, 0, 0, "", EvidenceStatus.OBSERVED.value)
            for h in compromised_hosts
        ]

        while queue and len(results) < _MAX_RESULTS:
            if time.monotonic() > deadline:
                logger.warning("ReachabilityEngine BFS timeout after %.1fs", _TIMEOUT_SEC)
                break

            host, depth, path_len, ev_uid, status = queue.pop(0)

            if depth >= _MAX_DEPTH:
                continue

            for dst_host, confirmed, link_ev_uid in self._topology.get_reachable_hosts(host):
                if dst_host in visited:
                    continue
                if len(results) >= _MAX_RESULTS:
                    break
                visited.add(dst_host)

                new_status = (
                    EvidenceStatus.OBSERVED.value if confirmed
                    else EvidenceStatus.NETWORK_REACHABLE.value
                )
                caveat = None
                if not self._topology.has_firewall_data() and not confirmed:
                    caveat = "Network policy data absent — reachability assumed from routing"

                item = ReachabilityItem(
                    asset_id=f"ASSET-{len(results)+1:03d}",
                    asset_name=dst_host,
                    asset_type=asset_types.get(dst_host, "Unknown"),
                    zone=zones.get(dst_host, "Unknown Zone"),
                    reachability_status=new_status,
                    observed_path_steps=path_len + 1 if confirmed else 0,
                    potential_path_steps=path_len + 1,
                    critical_data_stored=dst_host in crit,
                    traversal_evidence=f"Via {host}" if confirmed else None,
                    evidence_uid=link_ev_uid or ev_uid,
                    hop_depth=depth + 1,
                    caveat=caveat,
                )
                results.append(item)
                queue.append((dst_host, depth + 1, path_len + 1, link_ev_uid, new_status))

        # Privilege-based reachability for compromised users
        for user in compromised_users:
            if len(results) >= _MAX_RESULTS:
                break
            for priv_edge in self._privilege_graph.get_privilege_targets(user):
                target = priv_edge.target_asset
                if target in visited:
                    continue
                visited.add(target)
                item = ReachabilityItem(
                    asset_id=f"ASSET-PRIV-{len(results)+1:03d}",
                    asset_name=target,
                    asset_type=asset_types.get(target, "Unknown"),
                    zone=zones.get(target, "Unknown Zone"),
                    reachability_status=(
                        EvidenceStatus.OBSERVED.value
                        if priv_edge.confirmed
                        else EvidenceStatus.POTENTIAL.value
                    ),
                    observed_path_steps=1 if priv_edge.confirmed else 0,
                    potential_path_steps=1,
                    critical_data_stored=target in crit,
                    traversal_evidence=(
                        f"Privilege: {user} → {priv_edge.privilege_type}"
                        if priv_edge.confirmed else None
                    ),
                    evidence_uid=priv_edge.evidence_uid,
                    hop_depth=1,
                    caveat=None if priv_edge.confirmed else "No logon observed — privilege inferred from group membership",
                )
                results.append(item)

        logger.info(
            "ReachabilityEngine: %d results from %d host seeds, %d user seeds",
            len(results), len(compromised_hosts), len(compromised_users)
        )
        return results

    def to_dict_list(self, items: List[ReachabilityItem]) -> List[dict]:
        return [asdict(item) for item in items]

