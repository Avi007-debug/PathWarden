"""Track cryptographic hashes and ingestion status in manifest."""
import hashlib
import json
import os

class ManifestManager:
    def __init__(self, manifest_file: str = "data/inventory/manifest.json"):
        self.manifest_file = manifest_file

    def register_file(self, file_path: str):
        h = hashlib.sha256()
        with open(file_path, "rb") as f:
            while chunk := f.read(65536):
                h.update(chunk)
        return {"file": file_path, "sha256": h.hexdigest()}
