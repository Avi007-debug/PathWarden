"""PathWarden enumeration definitions aligned with P0 shared interface contract."""

from enum import Enum

class TerminalDisposition(str, Enum):
    """Exactly one terminal disposition per input record."""
    MALFORMED = "MALFORMED"
    DUPLICATE_DROPPED = "DUPLICATE_DROPPED"
    VALID_EXCLUDED = "VALID_EXCLUDED"
    ELIGIBLE = "ELIGIBLE"

class ParseStatus(str, Enum):
    """Parser result status separated from terminal disposition."""
    PARSED = "PARSED"
    PARTIAL = "PARTIAL"
    MALFORMED = "MALFORMED"
    UNSUPPORTED_FORMAT = "UNSUPPORTED_FORMAT"
    UNCLASSIFIED = "UNCLASSIFIED"

class Outcome(str, Enum):
    """Outcome when supported by source evidence."""
    SUCCESS = "SUCCESS"
    FAILURE = "FAILURE"
    UNKNOWN = "UNKNOWN"

class SeverityLevel(str, Enum):
    """Normalized severity using the shared vocabulary."""
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"
    UNKNOWN = "UNKNOWN"

class EvidenceStatus(str, Enum):
    """Distinguish observed facts, supported inference and possible reachability."""
    OBSERVED = "OBSERVED"
    INFERRED = "INFERRED"
    POTENTIAL = "POTENTIAL"

class KillChainStage(str, Enum):
    """Lockheed Martin 7-stage Cyber Kill Chain."""
    RECONNAISSANCE = "RECONNAISSANCE"
    WEAPONIZATION = "WEAPONIZATION"
    DELIVERY = "DELIVERY"
    EXPLOITATION = "EXPLOITATION"
    INSTALLATION = "INSTALLATION"
    COMMAND_AND_CONTROL = "COMMAND_AND_CONTROL"
    ACTIONS_ON_OBJECTIVES = "ACTIONS_ON_OBJECTIVES"

class EntityType(str, Enum):
    """Canonical entity types used across graph."""
    HOST = "host"
    USER = "user"
    PROCESS = "process"
    IP = "ip"
    DOMAIN = "domain"
    FILE = "file"
    SESSION = "session"

class RelationshipType(str, Enum):
    """Canonical graph relationship types."""
    SPAWNED = "spawned"
    AUTHENTICATED_TO = "authenticated_to"
    CONNECTED_TO = "connected_to"
    MODIFIED_FILE = "modified_file"
    INJECTED_SERVICE = "injected_service"
    SHARED_CREDENTIAL = "shared_credential"
    SHARED_HOST_TRAVERSAL = "shared_host_traversal"
    OBSERVED_SESSION = "observed_session"
    NETWORK_REACHABLE = "network_reachable"
    PRIVILEGE_RELATIONSHIP = "privilege_relationship"

class ConfidenceCategory(str, Enum):
    """Mapping & relationship confidence categories."""
    STRONG = "STRONG"
    MODERATE = "MODERATE"
    INFERRED = "INFERRED"
