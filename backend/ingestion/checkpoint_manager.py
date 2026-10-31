"""Persist ingestion byte offsets and chunk milestones for resumability."""
import json
import os

class CheckpointManager:
    def __init__(self, checkpoint_file: str = "data/inventory/checkpoint.json"):
        self.file = checkpoint_file

    def save_checkpoint(self, file_path: str, offset: int):
        data = self.load_all()
        data[file_path] = offset
        os.makedirs(os.path.dirname(self.file), exist_ok=True)
        with open(self.file, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

    def load_all(self):
        if os.path.exists(self.file):
            try:
                with open(self.file, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                return {}
        return {}
