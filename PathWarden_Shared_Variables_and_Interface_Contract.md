# PathWarden — Shared Variables & Interface Contract

Common data definitions across FR-1 to FR-7

# PathWarden — Shared Variables & Interface Contract

Common data definitions across FR-1 to FR-7

## 1. Shared identifiers

| Variable | Type | Shared meaning / rule |
| --- | --- | --- |
| event_uid | string | Unique PathWarden event ID generated during ingestion; stable downstream. |
| source_event_id | string \| null | Original ID supplied by the source; never substitute event_uid. |
| source_file_id | string | Stable identifier for an input file, linked to its manifest/checksum. |
| batch_id | string | Identifier for the ingestion batch or chunk. |
| detection_id | string | Unique ID for one detection/rule match. |
| incident_id | string \| null | ID assigned when FR-4 groups events into an incident. |
| entity_id | string | Canonical entity identifier used in the graph. |
| relationship_id | string | Unique identifier for a graph relationship. |
| host_id | string \| null | Resolved host identity; keep hostname/source identifiers too. |
| user_id | string \| null | Resolved user identity; preserve username and domain. |
| process_entity_id | string \| null | Stable process identity when available; PID alone is not globally unique. |
| session_id | string \| null | Source session identifier, when present. |

## 2. Canonical event schema — FR-1 output

| Field | Type | Requirement / meaning |
| --- | --- | --- |
| event_uid | string | Required; unique PathWarden event identifier. |
| source_event_id | string/null | Original source event ID. |
| event_ts | UTC timestamp/null | Event occurrence time; null if unavailable/unparseable. |
| event_ts_original | string/null | Original timestamp exactly as received. |
| ingest_ts | UTC timestamp | Time PathWarden ingested/processed the record. |
| source_type | string | Log source family or adapter identifier. |
| sensor_id | string/null | Agent, sensor or collector identifier. |
| event_category | string/null | Original source category, preserved. |
| event_type | string/null | Normalized event type when semantics are known. |
| action | string/null | Normalized action when semantics are known. |
| outcome | string/null | SUCCESS, FAILURE or UNKNOWN only when supported by evidence. |
| host_id / host_name | string/null | Resolved host ID and hostname; retain original values. |
| user_id / user_name | string/null | Resolved user ID and username; preserve domain/context. |
| src_ip / src_port | string/null; integer/null | Validated source address and port. |
| dst_ip / dst_port | string/null; integer/null | Validated destination address and port. |
| network_protocol | string/null | Normalized protocol where known. |
| process_id / parent_process_id | string/null | Process identifiers; scope PIDs to a host. |
| process_entity_id | string/null | Stable process entity ID, if available. |
| session_id | string/null | Session identifier, if present. |
| raw_event_reference | string | Reference back to original raw record. |
| parse_status | string/enum | Parser result status. |
| dq_flags | array[string] | Zero or more quality flags; flags can overlap. |
| extra | object/map | All source fields not mapped to canonical columns; do not discard unknown fields. |

## 3. Detection output contract — FR-2 / FR-3

| Field | Type | Meaning |
| --- | --- | --- |
| detection_id | string | Unique detection record ID. |
| rule_id / rule_name | string | Stable rule identifier and readable name. |
| rule_version | string | Version of the detection rule. |
| event_uids | array[string] | Events supporting the detection. |
| primary_event_uid | string/null | Main event associated with the detection, if applicable. |
| detected_at | UTC timestamp | Time the detection was generated. |
| severity | enum/string | Normalized severity using the shared vocabulary. |
| confidence | number/null | Detection score; document scale and meaning. |
| description | string | What condition was detected. |
| evidence | object/array | Relevant values and evidence references supporting the match. |
| mitre_technique_id | string/null | ATT&CK technique/sub-technique ID. |
| mitre_technique_name | string/null | Technique name from the pinned ATT&CK bundle. |
| mitre_tactic | string/null | ATT&CK tactic; separate from project kill-chain stage. |
| kill_chain_stage | string | Project-mapped stage; populated from agreed mapping. |
| kc_confidence | number/string | Mapping strength; agree one scale/representation. |
| mapping_reason | string | Reason and provenance for the mapping. |

## 4. Correlation and graph contract — FR-4 / FR-5 / FR-6

| Field | Type | Meaning |
| --- | --- | --- |
| incident_id | string | Stable incident/cluster identifier. |
| incident_event_uids | array[string] | Events assigned to the incident. |
| incident_detection_ids | array[string] | Detections supporting the incident. |
| entity_id | string | Canonical entity identifier. |
| entity_type | enum/string | Agreed type: host, user, process, IP, domain, file, session, etc. |
| relationship_id | string | Unique relationship identifier. |
| source_entity_id / target_entity_id | string | From-entity and to-entity identifiers. |
| relationship_type | string | Meaning, e.g. spawned, authenticated_to, connected_to. |
| relationship_score | number | Evidence-strength score; not a probability unless calibrated. |
| relationship_confidence | number/string | Optional confidence; use only if its scale is agreed. |
| evidence_event_uids | array[string] | Events supporting the relationship. |
| explanation | string | Human-readable reason for the relationship. |
| observed_or_inferred | enum | OBSERVED, INFERRED or POTENTIAL. |
| first_seen_ts / last_seen_ts | UTC timestamp/null | Earliest and latest supporting event times. |

## 5. Shared enumerations and conventions

| Concept | Agreed values / format | Rule |
| --- | --- | --- |
| Record disposition | MALFORMED \| DUPLICATE_DROPPED \| VALID_EXCLUDED \| ELIGIBLE | Exactly one terminal disposition per input record. |
| Parse status | PARSED \| PARTIAL \| MALFORMED \| UNSUPPORTED_FORMAT \| UNCLASSIFIED | Separate parser status from terminal disposition. |
| Outcome | SUCCESS \| FAILURE \| UNKNOWN | Do not infer success/failure when source evidence is absent. |
| Severity | INFO \| LOW \| MEDIUM \| HIGH \| CRITICAL \| UNKNOWN | Preserve original source severity in extra. |
| Evidence status | OBSERVED \| INFERRED \| POTENTIAL | Distinguish observed facts, supported inference and possible reachability. |
| Timestamp | UTC ISO-8601 / native Parquet timestamp | event_ts is event time; ingest_ts is processing time; retain original timestamp. |
| Missing values | null | Do not substitute empty strings or zero for missing values. |
| Unknown fields | extra object/map | Preserve unrecognized source fields and report them. |
| IDs | Stable strings | Never reuse an event_uid for a different event; preserve source IDs separately. |
| Scores | Documented numeric scale | A score is not a probability unless statistically calibrated. |

## 6. Cross-team interface rules

- FR-1 creates canonical event records and provenance. FR-2 consumes normalized events and emits detections.
- FR-3 enriches detections with ATT&CK and project kill-chain mapping. Keep mitre_tactic and kill_chain_stage separate.
- FR-4 references event_uid and detection_id; it should not rename or silently redefine them.
- FR-5 and FR-6 consume the same incident, entity, detection and relationship identifiers.
- Every detection and relationship must retain references to the event evidence supporting it.
- Use event_ts for event chronology and ingest_ts for processing chronology. Do not substitute file order for event time.
- Do not treat IP addresses as permanent host identities. Scope process IDs to hosts and preserve username domain context.
- Do not merge incidents solely because records share a timestamp, username, IP or host; require supporting evidence.
- Ground-truth labels belong only in evaluation code, not production ingestion, detection or correlation.
- Version the canonical schema, parsers, rules and mappings, and record the versions with outputs.
- Unknown but parseable fields and event categories must be preserved rather than silently discarded.
## 7. Decisions both teammates must finalize

- Exact canonical field names and data types.
- Timestamp serialization convention: UTC ISO-8601 strings or native Parquet timestamps.
- Allowed values for severity, outcome, parse_status and observed_or_inferred.
- Confidence/score scale and meaning; do not mix 0–1, 0–100 and named levels.
- Controlled vocabulary for entity_type and relationship_type.
- Generation and stability rules for event_uid, detection_id, incident_id and relationship_id.
- How raw_event_reference resolves to the original file and record/offset.