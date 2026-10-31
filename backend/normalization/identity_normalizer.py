"""Normalize usernames (UPN, SAMAccountName, SID) to lowercase domain format."""
class IdentityNormalizer:
    def normalize_user(self, user_str: str, domain: str = None) -> str:
        user = user_str.lower().strip()
        if "\" in user:
            return user
        if domain:
            return f"{domain.lower()}\\{user}"
        return user
