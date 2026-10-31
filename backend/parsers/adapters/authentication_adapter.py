"""Adapter for auth logon events."""
class AuthenticationAdapter:
    def adapt(self, record: dict) -> dict:
        return {
            "user_name": record.get("user", {}).get("name") or record.get("TargetUserName"),
            "domain": record.get("user", {}).get("domain") or record.get("TargetDomainName"),
            "logon_type": record.get("LogonType")
        }
