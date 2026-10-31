"""Map raw process, registry, and network signals to MITRE ATT&CK techniques."""
class AttackMapper:
    TACTIC_MAP = {
        "T1003.001": ("CREDENTIAL_ACCESS", "OS Credential Dumping: LSASS Memory"),
        "T1059.001": ("EXECUTION", "PowerShell Scripting Interpreter"),
        "T1550.002": ("LATERAL_MOVEMENT", "Pass the Hash Authentication"),
        "T1087.002": ("DISCOVERY", "Domain Account Discovery"),
        "T1543.003": ("PERSISTENCE", "Windows Service Creation"),
    }

    def map_technique(self, tech_id: str):
        if tech_id in self.TACTIC_MAP:
            tactic, name = self.TACTIC_MAP[tech_id]
            return {"technique_id": tech_id, "technique_name": name, "tactic": tactic}
        return {"technique_id": tech_id, "technique_name": "Unclassified Technique", "tactic": "EXECUTION"}
