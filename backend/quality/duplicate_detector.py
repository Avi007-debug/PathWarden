"""Detect duplicate events via surrogate event_id hashes."""
class DuplicateDetector:
    def __init__(self):
        self.seen_ids = set()

    def is_duplicate(self, event_id: str) -> bool:
        if event_id in self.seen_ids:
            return True
        self.seen_ids.add(event_id)
        return False
