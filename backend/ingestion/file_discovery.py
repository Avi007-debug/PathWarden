"""File discovery module for incoming telemetry directories."""
import os
from typing import List

def discover_files(directory: str, extensions: List[str]) -> List[str]:
    discovered = []
    for root, _, files in os.walk(directory):
        for f in files:
            if any(f.endswith(ext) for ext in extensions):
                discovered.append(os.path.join(root, f))
    return discovered
