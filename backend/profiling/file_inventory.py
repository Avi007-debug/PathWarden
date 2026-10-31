"""File inventory scanner for raw telemetry dumps."""
import os
import glob
from typing import List, Dict, Any

def scan_raw_files(data_dir: str) -> List[Dict[str, Any]]:
    results = []
    for filepath in glob.glob(os.path.join(data_dir, "**", "*"), recursive=True):
        if os.path.isfile(filepath) and not filepath.endswith(".gitkeep"):
            results.append({
                "path": filepath,
                "name": os.path.basename(filepath),
                "size_bytes": os.path.getsize(filepath),
                "extension": os.path.splitext(filepath)[1].lower()
            })
    return results
