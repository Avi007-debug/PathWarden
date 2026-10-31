"""Standardize high-level event taxonomy categories."""
class EventNormalizer:
    CATEGORY_MAP = {
        "1": "PROCESS_CREATE",
        "3": "NETWORK_CONNECT",
        "11": "FILE_CREATE",
        "4624": "AUTH_LOGIN"
    }

    def categorize_event(self, raw_code: str) -> str:
        return self.CATEGORY_MAP.get(str(raw_code), "OTHER")
