"""Correlate MITRE ATT&CK tactics to Lockheed Martin 7-stage Cyber Kill Chain."""
class KillChainMapper:
    STAGE_MAP = {
        "RECONNAISSANCE": "RECONNAISSANCE",
        "RESOURCE_DEVELOPMENT": "WEAPONIZATION",
        "INITIAL_ACCESS": "DELIVERY",
        "EXECUTION": "EXPLOITATION",
        "PRIVILEGE_ESCALATION": "EXPLOITATION",
        "PERSISTENCE": "INSTALLATION",
        "DEFENSE_EVASION": "INSTALLATION",
        "CREDENTIAL_ACCESS": "ACTIONS_ON_OBJECTIVES",
        "DISCOVERY": "ACTIONS_ON_OBJECTIVES",
        "LATERAL_MOVEMENT": "ACTIONS_ON_OBJECTIVES",
        "COLLECTION": "ACTIONS_ON_OBJECTIVES",
        "COMMAND_AND_CONTROL": "COMMAND_AND_CONTROL",
        "EXFILTRATION": "ACTIONS_ON_OBJECTIVES",
        "IMPACT": "ACTIONS_ON_OBJECTIVES"
    }

    def map_tactic_to_kc(self, tactic: str) -> str:
        return self.STAGE_MAP.get(tactic.upper().replace(" ", "_"), "ACTIONS_ON_OBJECTIVES")
