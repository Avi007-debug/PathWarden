"""UUID and deterministic surrogate key generators."""

import uuid
import hashlib

def generate_event_id(raw_str: str) -> str:
    """Generate deterministic SHA256 surrogate key for raw event string."""
    return f"EVT-{hashlib.sha256(raw_str.encode('utf-8')).hexdigest()[:16]}"

def generate_step_uid() -> str:
    """Generate unique attack step identifier."""
    return f"STEP-{uuid.uuid4().hex[:8].upper()}"

def generate_incident_id(index: int) -> str:
    """Generate sequential incident identifier."""
    return f"INC-2026-{index:04d}"

