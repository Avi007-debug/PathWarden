"""Collect and structure evidence details from DuckDB detection query results."""

from typing import Dict, Any, List, Tuple


class EvidenceCollector:
    """Structures evidence data and extracts event UIDs from detection rows."""

    def extract_evidence_and_uids(
        self,
        row: Dict[str, Any],
        rule: Dict[str, Any],
    ) -> Tuple[List[str], str, Dict[str, Any]]:
        """
        Parses a DuckDB row into (event_uids, primary_event_uid, evidence_dict).
        Handles both individual event rows and aggregated group rows.
        """
        event_uids: List[str] = []
        primary_uid: str = ""

        # Case 1: row has list of event_uids
        if "event_uids" in row and row["event_uids"] is not None:
            raw_uids = row["event_uids"]
            if isinstance(raw_uids, list):
                event_uids = [str(u) for u in raw_uids]
            elif isinstance(raw_uids, str):
                event_uids = [u.strip() for u in raw_uids.strip("[]").split(",") if u.strip()]

        # Case 2: row has single event_uid
        elif "event_uid" in row and row["event_uid"]:
            event_uids = [str(row["event_uid"])]

        # Determine primary event UID
        if "primary_event_uid" in row and row["primary_event_uid"]:
            primary_uid = str(row["primary_event_uid"])
        elif event_uids:
            primary_uid = event_uids[0]
        else:
            primary_uid = "UNKNOWN"

        # Construct structured evidence dictionary (excluding large raw columns)
        evidence: Dict[str, Any] = {
            "rule_id": rule.get("rule_id"),
            "event_count": len(event_uids),
        }

        # Add all contextual keys from row into evidence
        for k, v in row.items():
            if k in ("event_uids", "primary_event_uid", "extra"):
                continue
            if v is not None:
                evidence[k] = v

        return event_uids, primary_uid, evidence
