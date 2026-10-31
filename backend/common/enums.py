"""PathWarden enumeration definitions aligned with P0 shared interface contract.

Section 5 of the shared contract defines all allowed values. These enums enforce
at the Python level that no code can use an out-of-contract string by accident.

Key rules:
  - TerminalDisposition and ParseStatus are SEPARATE concepts. Do not conflate them.
  - TerminalDisposition: exactly ONE per record. Mutually exclusive. No record can be
    both MALFORMED and DUPLICATE_DROPPED.
  - ParseStatus: describes what the parser was able to do, not what happened to the record.
  - DQFlag: non-terminal quality annotations. Multiple flags CAN apply to one record.
  - Severity/Outcome: only use when source evidence actually supports the value.
    Never infer SUCCESS or FAILURE when the source does not say so.
"""

from enum import Enum


class TerminalDisposition(str, Enum):
    """Exactly one terminal disposition per input record (mutually exclusive).

    The reconciliation invariant enforced by quality/reconciliation.py:
        records_read == MALFORMED + DUPLICATE_DROPPED + VALID_EXCLUDED + ELIGIBLE

    - MALFORMED        : record could not be parsed at all (corrupt bytes, truncation).
    - DUPLICATE_DROPPED: record is a confirmed duplicate of an already-ingested event.
    - VALID_EXCLUDED   : record parsed cleanly but falls outside the ingestion scope
                         (e.g. out-of-window timestamp, excluded source type).
    - ELIGIBLE         : record passed all checks and was written to Parquet storage.
    """
    MALFORMED         = "MALFORMED"
    DUPLICATE_DROPPED = "DUPLICATE_DROPPED"
    VALID_EXCLUDED    = "VALID_EXCLUDED"
    ELIGIBLE          = "ELIGIBLE"


class ParseStatus(str, Enum):
    """Parser result — what the parser was able to extract.

    Separate from TerminalDisposition. A PARTIAL parse may still yield an ELIGIBLE
    record if the critical fields (event_uid, event_ts, source_type) are present.

    - PARSED            : all expected fields extracted successfully.
    - PARTIAL           : some fields extracted; others missing or unparseable.
    - MALFORMED         : record could not be structurally parsed at all.
    - UNSUPPORTED_FORMAT: file/line format not handled by any registered parser.
    - UNCLASSIFIED      : format was detected but semantic mapping is unknown.
    """
    PARSED             = "PARSED"
    PARTIAL            = "PARTIAL"
    MALFORMED          = "MALFORMED"
    UNSUPPORTED_FORMAT = "UNSUPPORTED_FORMAT"
    UNCLASSIFIED       = "UNCLASSIFIED"


class DQFlag(str, Enum):
    """Non-terminal data quality flags. Multiple flags may apply to one record.

    These do NOT replace TerminalDisposition. They annotate the event record's
    dq_flags list and are preserved in Parquet output for downstream consumers.

    - TIMESTAMP_UNCERTAIN : timestamp parsed but reliability is low (e.g. no timezone).
    - TIMESTAMP_MISSING   : no timestamp field found; event_ts will be null.
    - HOST_INFERRED       : host_name derived from context, not a direct source field.
    - USER_INFERRED       : user_name derived from context, not a direct source field.
    - UNKNOWN_EVENT_TYPE  : event_type could not be mapped to a canonical type.
    - IP_VALIDATION_FAILED: src_ip or dst_ip failed RFC-compliant validation.
    - PARTIAL_PARSE       : some fields missing; canonical record is incomplete.
    - EXTRA_FIELDS_PRESENT: source had fields not in canonical schema (stored in extra).
    """
    TIMESTAMP_UNCERTAIN  = "TIMESTAMP_UNCERTAIN"
    TIMESTAMP_MISSING    = "TIMESTAMP_MISSING"
    HOST_INFERRED        = "HOST_INFERRED"
    USER_INFERRED        = "USER_INFERRED"
    UNKNOWN_EVENT_TYPE   = "UNKNOWN_EVENT_TYPE"
    IP_VALIDATION_FAILED = "IP_VALIDATION_FAILED"
    PARTIAL_PARSE        = "PARTIAL_PARSE"
    EXTRA_FIELDS_PRESENT = "EXTRA_FIELDS_PRESENT"


class Outcome(str, Enum):
    """Normalized outcome. Only set when source evidence explicitly supports it.

    Contract rule: do NOT substitute UNKNOWN when no evidence is present.
    Leave the field null instead. Only emit SUCCESS/FAILURE when the raw log
    says so (e.g. Windows Event 4624 = SUCCESS, 4625 = FAILURE).
    """
    SUCCESS = "SUCCESS"
    FAILURE = "FAILURE"
    UNKNOWN = "UNKNOWN"


class SeverityLevel(str, Enum):
    """Normalized severity. Original source severity is preserved in extra.

    Scale: INFO < LOW < MEDIUM < HIGH < CRITICAL.
    UNKNOWN is used when a severity field exists but cannot be mapped to this scale.
    """
    INFO     = "INFO"
    LOW      = "LOW"
    MEDIUM   = "MEDIUM"
    HIGH     = "HIGH"
    CRITICAL = "CRITICAL"
    UNKNOWN  = "UNKNOWN"


class EvidenceStatus(str, Enum):
    """Distinguish observed facts from inference and possible reachability.

    Used in detection records and graph relationships (FR-3, FR-4, FR-6).
    - OBSERVED  : directly supported by one or more raw log events.
    - INFERRED  : logically derived from observed events; not directly logged.
    - POTENTIAL : possible based on graph reachability; not yet confirmed.
    """
    OBSERVED  = "OBSERVED"
    INFERRED  = "INFERRED"
    POTENTIAL = "POTENTIAL"


class KillChainStage(str, Enum):
    """Lockheed Martin 7-stage Cyber Kill Chain (project mapping).

    IMPORTANT: This is the PROJECT kill-chain stage, not the ATT&CK tactic.
    Keep kill_chain_stage and mitre_tactic SEPARATE in all detection records.
    Mapping lives in config/attack_to_kc.yaml.
    """
    RECONNAISSANCE        = "RECONNAISSANCE"
    WEAPONIZATION         = "WEAPONIZATION"
    DELIVERY              = "DELIVERY"
    EXPLOITATION          = "EXPLOITATION"
    INSTALLATION          = "INSTALLATION"
    COMMAND_AND_CONTROL   = "COMMAND_AND_CONTROL"
    ACTIONS_ON_OBJECTIVES = "ACTIONS_ON_OBJECTIVES"


class EntityType(str, Enum):
    """Canonical entity types used in the graph (FR-4 / FR-5).

    Contract vocabulary: host, user, process, ip, domain, file, session.
    Do not introduce new types without updating the shared contract.
    """
    HOST    = "host"
    USER    = "user"
    PROCESS = "process"
    IP      = "ip"
    DOMAIN  = "domain"
    FILE    = "file"
    SESSION = "session"


class RelationshipType(str, Enum):
    """Canonical graph relationship types (FR-4 / FR-5).

    - SPAWNED          : process A created process B.
    - AUTHENTICATED_TO : user authenticated to a host or service.
    - CONNECTED_TO     : network connection from entity A to entity B.
    """
    SPAWNED               = "spawned"
    AUTHENTICATED_TO      = "authenticated_to"
    CONNECTED_TO          = "connected_to"
    MODIFIED_FILE         = "modified_file"
    INJECTED_SERVICE      = "injected_service"
    SHARED_CREDENTIAL     = "shared_credential"
    SHARED_HOST_TRAVERSAL = "shared_host_traversal"
    OBSERVED_SESSION      = "observed_session"
    NETWORK_REACHABLE     = "network_reachable"
    PRIVILEGE_RELATIONSHIP = "privilege_relationship"


class ConfidenceCategory(str, Enum):
    """Mapping and relationship confidence levels.

    Named levels, NOT numeric probabilities (contract section 5 / section 7).
    - STRONG  : direct, unambiguous evidence from the source log.
    - MODERATE: evidence present but with some ambiguity or inference.
    - INFERRED: derived from indirect indicators; no direct log evidence.
    """
    STRONG   = "STRONG"
    MODERATE = "MODERATE"
    INFERRED = "INFERRED"
