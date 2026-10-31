"""PathWarden FR-6: Privilege graph builder.

Derives user → group → asset privilege relationships from authentication events
in Parquet.  Only emits PRIVILEGE_RELATIONSHIP edges when group membership is
confirmed in logs (not assumed from naming conventions).
"""

from __future__ import annotations

import os
import glob
from collections import defaultdict
from typing import Dict, List, Set, Optional, Tuple

import duckdb

from common.logger import get_logger

logger = get_logger("PrivilegeGraph")


class PrivilegeEdge:
    """Represents a confirmed privilege relationship between user and target asset."""
    __slots__ = ("user_entity", "target_asset", "privilege_type", "evidence_uid", "confirmed")

    def __init__(
        self,
        user_entity: str,
        target_asset: str,
        privilege_type: str,
        evidence_uid: str,
        confirmed: bool = False,
    ) -> None:
        self.user_entity = user_entity
        self.target_asset = target_asset
        self.privilege_type = privilege_type
        self.evidence_uid = evidence_uid
        self.confirmed = confirmed


class PrivilegeGraph:
    """Builds user privilege graph from auth event logs in Parquet."""

    def __init__(self, data_dir: str) -> None:
        self.data_dir = data_dir
        # user_entity → list of PrivilegeEdge
        self._user_privileges: Dict[str, List[PrivilegeEdge]] = defaultdict(list)
        # user_entity → set of group_names
        self._group_membership: Dict[str, Set[str]] = defaultdict(set)
        self._built = False

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def build(self, con: Optional[duckdb.DuckDBPyConnection] = None) -> None:
        """Populate privilege graph from Parquet auth events."""
        owns_con = con is None
        if owns_con:
            con = duckdb.connect(":memory:")
        try:
            self._register_views(con)
            self._extract_auth_privileges(con)
            self._built = True
            logger.info(
                "PrivilegeGraph built: %d users with privilege entries",
                len(self._user_privileges)
            )
        finally:
            if owns_con:
                con.close()

    def get_privilege_targets(self, user_entity: str) -> List[PrivilegeEdge]:
        """Return all privilege edges for the given canonical user entity_id."""
        if not self._built:
            logger.warning("PrivilegeGraph.build() not called")
            return []
        return self._user_privileges.get(user_entity, [])

    def get_groups(self, user_entity: str) -> Set[str]:
        return self._group_membership.get(user_entity, set())

    def all_privileged_users(self) -> List[str]:
        return list(self._user_privileges.keys())

    # ------------------------------------------------------------------
    # Private
    # ------------------------------------------------------------------

    def _register_views(self, con: duckdb.DuckDBPyConnection) -> None:
        events_glob = os.path.join(self.data_dir, "events", "*.parquet").replace("\\", "/")
        if glob.glob(os.path.join(self.data_dir, "events", "*.parquet")):
            con.execute(f"CREATE OR REPLACE VIEW auth_events AS SELECT * FROM read_parquet('{events_glob}')")
        else:
            con.execute("""
                CREATE OR REPLACE VIEW auth_events AS
                SELECT ''::VARCHAR AS user_name, ''::VARCHAR AS host_name,
                       ''::VARCHAR AS event_type, ''::VARCHAR AS group_name,
                       ''::VARCHAR AS event_uid, FALSE::BOOLEAN AS auth_success
                WHERE 1=0
            """)

    def _extract_auth_privileges(self, con: duckdb.DuckDBPyConnection) -> None:
        """Extract explicit auth successes and group membership events."""
        # Successful auth = confirmed privilege
        try:
            auth_rows = con.execute("""
                SELECT user_name, host_name, event_uid
                FROM auth_events
                WHERE event_type IN (
                    'authentication_success', 'kerberos_ticket_grant',
                    'smb_auth_success', 'ssh_auth_success'
                )
                  AND user_name IS NOT NULL AND user_name != ''
                  AND host_name IS NOT NULL AND host_name != ''
                GROUP BY user_name, host_name, event_uid
            """).fetchall()
        except Exception as exc:  # noqa: BLE001
            logger.warning("PrivilegeGraph auth extraction failed: %s", exc)
            auth_rows = []

        for uname, host, ev_uid in auth_rows:
            user_entity = f"user:{uname.lower()}"
            edge = PrivilegeEdge(
                user_entity=user_entity,
                target_asset=host,
                privilege_type="authenticated_access",
                evidence_uid=ev_uid or "",
                confirmed=True,
            )
            self._user_privileges[user_entity].append(edge)

        # Group membership events
        try:
            grp_rows = con.execute("""
                SELECT user_name, group_name, event_uid
                FROM auth_events
                WHERE event_type IN ('group_membership_added', 'group_membership_enumerated')
                  AND group_name IS NOT NULL AND group_name != ''
                  AND user_name IS NOT NULL AND user_name != ''
                GROUP BY user_name, group_name, event_uid
            """).fetchall()
        except Exception:  # noqa: BLE001
            grp_rows = []

        for uname, grp, ev_uid in grp_rows:
            user_entity = f"user:{uname.lower()}"
            self._group_membership[user_entity].add(grp)
            # High-privilege groups implicitly grant DC/domain asset access
            if any(kw in grp.lower() for kw in ("domain admin", "enterprise admin", "schema admin")):
                edge = PrivilegeEdge(
                    user_entity=user_entity,
                    target_asset=f"domain_group:{grp}",
                    privilege_type=f"member_of:{grp}",
                    evidence_uid=ev_uid or "",
                    confirmed=True,
                )
                self._user_privileges[user_entity].append(edge)

