"""Profile distribution of event action types and frequencies."""
from collections import Counter
from typing import List, Dict, Any

class EventProfiler:
    def __init__(self):
        self.actions = Counter()

    def add_event(self, action_name: str):
        self.actions[action_name] += 1

    def top_actions(self, n: int = 10):
        return self.actions.most_common(n)
