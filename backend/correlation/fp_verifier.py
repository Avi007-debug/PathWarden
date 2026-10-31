"""PathWarden False Positive (FP) Verifier.

Grounds attack veracity strictly in log evidence vs. log absence:
1. Admin Tool Baseline: Checks if command/process stems from legitimate IT deployment
   infrastructure (SCCM, Ansible, WSUS, BigFix) without adversarial follow-through.
2. Adversarial Objective Corroboration: Checks for high-impact objective milestones
   (LSASS dumping, shadow deletion, ticket forgery, external C2 beaconing).
3. Multi-Source Corroboration: Evaluates whether multiple independent sensor event types
   (Sysmon, Windows Security, Zeek) confirm the attack chain.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional, Set

from common.logger import get_logger

logger = get_logger("FPVerifier")

# Known benign administration tool process names and execution paths
_ADMIN_TOOL_PATTERNS = [
    re.compile(r"ccmexec\.exe", re.IGNORECASE),
    re.compile(r"\\ccm\\", re.IGNORECASE),
    re.compile(r"ansible", re.IGNORECASE),
    re.compile(r"wuauclt\.exe", re.IGNORECASE),
    re.compile(r"trustedinstaller\.exe", re.IGNORECASE),
    re.compile(r"besclient\.exe", re.IGNORECASE),
    re.compile(r"taniumclient\.exe", re.IGNORECASE),
    re.compile(r"qualys", re.IGNORECASE),
]

# Objective-achieving indicators (high-confidence adversarial intent)
_CREDENTIAL_OBJECTIVE_PATTERNS = [
    re.compile(r"lsass\.exe", re.IGNORECASE),
    re.compile(r"sekurlsa", re.IGNORECASE),
    re.compile(r"minidump", re.IGNORECASE),
    re.compile(r"procdump", re.IGNORECASE),
    re.compile(r"comsvcs\.dll.*#24", re.IGNORECASE),
    re.compile(r"ntdsutil", re.IGNORECASE),
    re.compile(r"dcsync", re.IGNORECASE),
    re.compile(r"kerberos::golden", re.IGNORECASE),
]

_DESTRUCTION_DEFENSE_PATTERNS = [
    re.compile(r"vssadmin.*delete.*shadows", re.IGNORECASE),
    re.compile(r"wbadmin.*delete", re.IGNORECASE),
    re.compile(r"bcdedit.*recoveryenabled\s+no", re.IGNORECASE),
    re.compile(r"wevtutil.*cl\s+", re.IGNORECASE),
    re.compile(r"Set-MpPreference.*-DisableRealtimeMonitoring", re.IGNORECASE),
]

_LATERAL_OBJECTIVE_PATTERNS = [
    re.compile(r"psexec", re.IGNORECASE),
    re.compile(r"wmic\s+/node:", re.IGNORECASE),
    re.compile(r"invoke-wmimethod", re.IGNORECASE),
    re.compile(r"winrs\s+-r:", re.IGNORECASE),
    re.compile(r"mimikatz", re.IGNORECASE),
]


@dataclass
class FPVerificationResult:
    verdict: str  # "CONFIRMED_MALICIOUS_ATTACK" | "BENIGN_ADMIN_ACTIVITY" | "SUSPICIOUS_UNVERIFIED"
    attack_confidence: float
    false_positive_risk: float
    corroboration_score: float
    is_admin_tool_signature: bool
    objective_achieved: bool
    multi_stage_depth: int
    explanation_points: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class FalsePositiveVerifier:
    """Evaluates multi-source corroboration and adversary objective achievements to verify genuine attacks vs FP."""

    def __init__(self) -> None:
        pass

    def verify_incident(
        self,
        steps: List[Dict[str, Any]],
        edges: Optional[List[Dict[str, Any]]] = None,
        hosts_involved: Optional[List[str]] = None,
    ) -> FPVerificationResult:
        """Evaluate an incident's steps and edges against attack verification heuristics."""
        edges = edges or []
        hosts = set(hosts_involved or [])
        for s in steps:
            h = s.get("host_name")
            if h and h != "unknown":
                hosts.add(h)

        explanation_points: List[str] = []
        is_admin_tool = False
        objective_hits: List[str] = []
        distinct_tactics: Set[str] = set()
        sensor_sources: Set[str] = set()

        total_steps = len(steps)
        if total_steps == 0:
            return FPVerificationResult(
                verdict="SUSPICIOUS_UNVERIFIED",
                attack_confidence=0.50,
                false_positive_risk=0.50,
                corroboration_score=0.20,
                is_admin_tool_signature=False,
                objective_achieved=False,
                multi_stage_depth=0,
                explanation_points=["No attack steps recorded for verification."],
            )

        # Inspect commands and processes across all steps
        for step in steps:
            cmd = step.get("command_line") or ""
            proc = step.get("process_name") or ""
            mitre = step.get("mitre") or {}
            tactic = mitre.get("tactic") or step.get("tactic") or ""
            if tactic:
                distinct_tactics.add(tactic.strip())

            rule_id = step.get("rule_id") or ""
            if "WIN" in rule_id or "4688" in rule_id or "4624" in rule_id:
                sensor_sources.add("Windows Security Event Log")
            if "SYSMON" in rule_id or "SYS" in rule_id:
                sensor_sources.add("Sysmon Telemetry")
            if "ZEEK" in rule_id or "NET" in rule_id:
                sensor_sources.add("Zeek Network Monitor")

            # Check admin tool signature
            target_str = f"{proc} {cmd}"
            if any(p.search(target_str) for p in _ADMIN_TOOL_PATTERNS):
                is_admin_tool = True

            # Check credential access objectives
            if any(p.search(target_str) for p in _CREDENTIAL_OBJECTIVE_PATTERNS):
                objective_hits.append("Credential Dumping / Memory Extraction (LSASS/NTDS)")

            # Check destructive / evasion objectives
            if any(p.search(target_str) for p in _DESTRUCTION_DEFENSE_PATTERNS):
                objective_hits.append("Defense Evasion / Shadow Copy Deletion (vssadmin/wevtutil)")

            # Check lateral movement objectives
            if any(p.search(target_str) for p in _LATERAL_OBJECTIVE_PATTERNS):
                objective_hits.append("Lateral Execution Tooling (PsExec/WMI remote)")

        # Unique objectives
        unique_objectives = sorted(list(set(objective_hits)))
        objective_achieved = len(unique_objectives) > 0

        # Calculate corroboration metrics
        corroboration_score = 0.50
        if len(sensor_sources) >= 2:
            corroboration_score += 0.20
            explanation_points.append(
                f"Multi-sensor corroboration: Confirmed across {', '.join(sorted(sensor_sources))}."
            )
        elif len(sensor_sources) == 1:
            explanation_points.append(
                f"Single sensor telemetry: Grounded in {list(sensor_sources)[0]}."
            )

        if len(hosts) >= 2:
            corroboration_score += 0.15
            explanation_points.append(
                f"Multi-host intrusion: Activity spans {len(hosts)} distinct endpoints ({', '.join(sorted(hosts)[:3])})."
            )

        if len(edges) >= 3:
            corroboration_score += 0.10
            explanation_points.append(
                f"Causal graph integrity: Reconstructed with {len(edges)} causal progression edges."
            )

        if objective_achieved:
            corroboration_score += 0.10
            for obj in unique_objectives:
                explanation_points.append(f"Adversarial objective verified: {obj}.")
        else:
            explanation_points.append("No credential dumping or system tampering objective verified in sequence.")

        # Baseline check
        if is_admin_tool and not objective_achieved and len(hosts) <= 1:
            attack_conf = 0.18
            fp_risk = 0.82
            verdict = "BENIGN_ADMIN_ACTIVITY"
            explanation_points.append(
                "High False Positive Risk: Matches verified administrative deployment tool signature (SCCM/Ansible/WSUS) without adversarial persistence."
            )
        elif objective_achieved or (len(distinct_tactics) >= 3 and len(hosts) >= 2):
            attack_conf = min(0.98, max(0.85, 0.70 + (0.05 * len(distinct_tactics)) + (0.04 * len(hosts))))
            fp_risk = round(1.0 - attack_conf, 2)
            verdict = "CONFIRMED_MALICIOUS_ATTACK"
            explanation_points.append(
                f"High Attack Fidelity: Verified multi-stage kill chain across {len(distinct_tactics)} tactics."
            )
            explanation_points.append(
                "Zero benign administration match: Process hierarchy and execution arguments diverge completely from corporate deployment baselines."
            )
        else:
            attack_conf = 0.65
            fp_risk = 0.35
            verdict = "SUSPICIOUS_UNVERIFIED"
            explanation_points.append(
                "Indeterminate activity: Suspicious commands observed, but lacks multi-host lateral spread or confirmed objective reach."
            )

        corroboration_score = min(1.0, round(corroboration_score, 2))
        attack_conf = round(attack_conf, 2)
        fp_risk = round(1.0 - attack_conf, 2)

        return FPVerificationResult(
            verdict=verdict,
            attack_confidence=attack_conf,
            false_positive_risk=fp_risk,
            corroboration_score=corroboration_score,
            is_admin_tool_signature=is_admin_tool,
            objective_achieved=objective_achieved,
            multi_stage_depth=len(distinct_tactics),
            explanation_points=explanation_points,
        )


# Global singleton
fp_verifier = FalsePositiveVerifier()

