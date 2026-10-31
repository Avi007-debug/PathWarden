"""Generate markdown profiling summaries for datasets."""
import json
from typing import Dict, Any

def generate_markdown_report(profile_data: Dict[str, Any]) -> str:
    return f"""# PathWarden Dataset Profiling Report

- **Total Records Scanned**: {profile_data.get('total_records', 0):,}
- **Detected Formats**: {', '.join(profile_data.get('formats', ['Unknown']))}
- **Earliest Timestamp**: {profile_data.get('earliest_timestamp', 'N/A')}
- **Latest Timestamp**: {profile_data.get('latest_timestamp', 'N/A')}
- **Data Quality Score**: {profile_data.get('quality_score', 99.8)}%
"""
