# PathWarden v5 - Refined Implementation Plan

## Kill Chain and Attack Path Reconstruction \| 30 GB Advanced Tier \| 24-hour hackathon \| Team of 2

**Status:** Recommended implementation baseline\
**Primary target:** 30 GB Advanced tier (1.3×), subject to organizer
confirmation that this is the selected tier\
**Hardware:** 16 GB RAM, 8 CPU cores, local execution, no cloud\
**Design principle:** Build an evidence-backed attack reconstruction
engine, not a generic SIEM dashboard.

------------------------------------------------------------------------

## 1. Executive decision

PathWarden will ingest heterogeneous security logs, normalize them into
a common event model, detect suspicious activity, map detections to
MITRE ATT&CK, correlate evidence across hosts/users/IPs, reconstruct
incidents as ordered attack paths, and show both observed activity and
potential reachability.

The team should target the **30 GB Advanced tier**. Do not target 50 GB
as the primary deliverable on a 16 GB local machine during a 24-hour
event. Keep the implementation out-of-core so 50 GB remains a possible
later benchmark, but only attempt it after the 30 GB acceptance gates
pass and only if the organizers allow changing tiers.

### Non-negotiable engineering principles

1.  **Dataset-first:** implement parsers and detections for the actual
    downloaded logs, not hypothetical sources.
2.  **Ground-truth isolation:** ground truth is used only by the
    evaluator and test harness, never by production detection or
    correlation.
3.  **Evidence before inference:** every detection and graph edge must
    retain the evidence that supports it.
4.  **Separate identity from attack correlation:** sharing a
    user/IP/host does not automatically mean two events belong to one
    attack.
5.  **Separate observed from potential:** confirmed log activity must
    never be presented as confirmed future access.
6.  **Bounded memory:** no full-dataset Pandas DataFrame, unbounded
    queues, or full raw-event graph.
7.  **Measure end-to-end:** benchmark ingestion through incident-ready
    output, not just file reading.
8.  **Scope discipline:** finish and validate FR-1 through FR-7 before
    optional features.

------------------------------------------------------------------------

## 2. Problem statement and success criteria

The system must meet the three central requirements:

1.  Detect suspicious events and label them with MITRE ATT&CK techniques
    and Cyber Kill Chain stages.
2.  Link related events across hosts, users, IPs and time into coherent
    attack paths without exhausting memory.
3.  Explain the reconstructed incident through a timeline, entity/attack
    graph, and evidence-backed assessment of what the attacker could
    potentially reach next.

### Competition metrics

Use the organizer's exact scoring implementation if supplied. The
following operational definitions are recommended until the official
scorer clarifies them.

  -------------------------------------------------------------------------------
  Metric          Operational      Good threshold Great threshold Internal target
                  definition                                      
  --------------- --------------- --------------- --------------- ---------------
  Detection       Planted attack            \>70%           \>90%            ≥92%
                  steps detected                                  
                  / total planted                                 
                  attack steps                                    

  Correct labels  Correct ATT&CK            \>60%           \>85%            ≥88%
                  technique                                       
                  labels /                                        
                  detected                                        
                  planted steps                                   
                  with a label                                    

  Attack path     Planted attacks            Half             All             All
                  reconstructed                                   
                  with correct                                    
                  required steps                                  
                  and order                                       

  False alarms    Generated                 \<30%           \<10%             ≤8%
                  incidents that                                  
                  are not                                         
                  planted/valid                                   
                  attacks / all                                   
                  generated                                       
                  incidents                                       

  Processing time Full selected             \<3 h           \<1 h         ≤45 min
                  tier from run                                   
                  start to                                        
                  incidents ready                                 

  Memory          Peak memory             \<16 GB          \<8 GB   Target ≤7 GB;
                  during                                           hard container
                  processing                                             cap 8 GB

  Investigation   Time to                   \<2 s        \<500 ms         ≤200 ms
  speed           retrieve one                                    
                  precomputed                                     
                  incident path                                   
  -------------------------------------------------------------------------------

**Important:** Confirm the exact denominator and matching rules for each
metric with the organizer's scorer. In particular, do not assume that a
technique/time match alone identifies a planted step. Matching may
require host, event ID, attack ID, source/destination, or a time
tolerance.

### Tier decision

  Tier          Size   Multiplier Decision
  ---------- ------- ------------ ------------------------------------
  Core         15 GB         1.0× Useful for early validation
  Advanced     30 GB         1.3× Primary competition target
  Extreme      50 GB         1.6× Stretch only after Advanced passes

The uploaded judging sheet says the tier's larger multiplier is
conditional on accuracy staying above the minimum bar. Confirm whether
the chosen tier is locked before the run begins. Do not assume a 30 GB
result can be upgraded to 50 GB after the fact.

------------------------------------------------------------------------

## 3. Scope and priorities

### P0 - Core engine

-   FR-1: dataset ingestion, parsing, normalization and bounded-memory
    storage.
-   FR-2: suspicious-event detection.
-   FR-3: MITRE ATT&CK and Cyber Kill Chain classification.
-   FR-4: evidence correlation, incident clustering and attack-path
    reconstruction.
-   Evaluation scorer and data-quality accounting are foundational
    enablers.

### P1 - Required presentation and access

-   FR-5: incident timeline and host/user/attack graph.
-   FR-6: observed and potential reachability.
-   FR-7: API, simple interface, packaging and README.

### P2 - Bonus only after P0/P1 pass

Implement in this order if time remains:

1.  Risk ranking.
2.  Deterministic incident report.
3.  Alert-to-incident aggregation/funnel.
4.  Configuration-driven rule addition demonstration.
5.  Live tailing/micro-batch updates.

Do not spend hackathon time on a chatbot, Neo4j, a complex LLM agent,
full Sigma compatibility, a synthetic dataset generator, or elaborate
exports before the core pipeline is correct.

------------------------------------------------------------------------

## 4. H0: Inspect the actual downloaded datasets

Because the logs have already been downloaded, this is the first
technical activity. Do not start by writing generic adapters.

### 4.1 Dataset inventory

Produce a machine-readable inventory with:

-   Dataset/tier name and total byte size.
-   File count and directory structure.
-   File extensions and detected formats.
-   Compression type.
-   File sizes and largest files.
-   Record count where cheaply measurable.
-   Earliest/latest timestamps from a sample.
-   Candidate source type.
-   Whether files are independent or parts of one stream.

### 4.2 Schema reconnaissance

For each distinct file format/source, inspect representative records and
record:

-   Timestamp field and format, timezone and precision.
-   Event identifier, if present.
-   Host/device identifier.
-   Username/account identifier.
-   Source/destination IP and port.
-   Process ID and parent process ID.
-   Session/logon ID.
-   Event/action type and outcome.
-   Sensor/source identifier.
-   Fields needed by planted attack steps.

Do not infer that a field is absent after inspecting only one record.
Measure field coverage across a representative sample.

### 4.3 Ground-truth reconnaissance

Inspect the ground-truth format and document:

-   Attack/incident identifiers.
-   Planted step identifiers.
-   Expected event IDs or matching keys.
-   Host/user/IP attributes.
-   Expected ATT&CK technique/sub-technique.
-   Expected order and timestamp tolerance.
-   Whether one planted step maps to multiple raw records.
-   How benign decoys or false-positive cases are represented.

Create a written matching contract before implementing the scorer.

**Ground truth must not be imported by the runtime detector, correlation
engine, or dashboard.** Keep it in a test/evaluation-only directory and
ensure production modules cannot read it.

### 4.4 H0 deliverable

`dataset_profile.json` plus a short human-readable report containing the
inventory, schema, field coverage, ground-truth contract, disk estimate
and recommended parser for each source.

------------------------------------------------------------------------

## 5. Normalized event model

Use one canonical schema while retaining source-specific fields in
`extra`.

Recommended minimum fields:

``` json
{
  "event_uid": "stable-source-derived-id",
  "source_file_id": "manifest-id",
  "source_type": "windows|linux|firewall|network|other",
  "sensor_id": null,
  "event_ts": "UTC timestamp",
  "ingest_ts": "UTC timestamp",
  "timestamp_precision": "millisecond",
  "timestamp_confidence": 1.0,
  "event_type": "authentication",
  "action": "logon",
  "outcome": "success",
  "host_id": null,
  "host_name": null,
  "user_id": null,
  "src_ip": null,
  "src_port": null,
  "dst_ip": null,
  "dst_port": null,
  "protocol": null,
  "process_id": null,
  "parent_process_id": null,
  "session_id": null,
  "record_id": null,
  "parse_status": "valid",
  "host_inferred": false,
  "ts_inferred": false,
  "is_late": false,
  "dq_flags": [],
  "extra": {}
}
```

### Schema rules

-   Store timestamps in UTC and retain original timezone/offset in
    `extra` if needed.
-   Do not invent a host, user, process or timestamp. Inferred values
    must be explicitly flagged and assigned lower confidence.
-   Use a stable identity based on source file identity plus record ID
    or byte offset. Do not use a small, collision-prone integer packing
    scheme.
-   For compressed files, distinguish compressed byte offset from
    decompressed record position. A gzip byte offset is not necessarily
    a directly seekable record location.
-   Preserve enough source reference information to retrieve the
    original raw record.
-   Keep identifiers as strings where leading zeros or source-specific
    formatting matter.
-   Do not discard unknown fields; preserve them under `extra`.

### Data-quality terminal dispositions

Every input record must have exactly one terminal disposition:

-   `MALFORMED`
-   `DUPLICATE_DROPPED`
-   `VALID_EXCLUDED`
-   `ELIGIBLE`

Quality flags such as `HOST_INFERRED`, `TIMESTAMP_UNCERTAIN` and
`UNKNOWN_EVENT_TYPE` are separate and may coexist with a terminal
disposition.

Reconciliation:

``` text
records_read =
    malformed
  + duplicate_dropped
  + valid_excluded
  + eligible
```

This prevents overlapping categories from being double-counted.

Deduplicate only on reliable source-specific identity. Identical
repeated failed-login records must be retained unless the source proves
they are duplicate deliveries.

------------------------------------------------------------------------

## 6. FR-1: Ingestion and storage

### 6.1 Parser strategy

Choose the parser after H0:

  -----------------------------------------------------------------------
  Actual input                        Preferred starting approach
  ----------------------------------- -----------------------------------
  CSV                                 DuckDB CSV reader or PyArrow, with
                                      rejected-row capture

  JSONL/NDJSON                        DuckDB JSON reader if schema is
                                      compatible; otherwise `orjson`
                                      streaming

  Nested/irregular JSON               `orjson` with source-specific
                                      normalization

  Syslog text                         Source-specific parser; preserve
                                      original line

  Compressed files                    Sequential decompression unless
                                      format supports safe parallel
                                      splitting
  -----------------------------------------------------------------------

Do not build a generic parser framework for formats that are not in the
downloaded data.

### 6.2 Parallelism

Use file-level parallelism first when there are multiple independent
files. Use record-boundary-aware chunking for very large files.

Starting settings for an 8-core, 16 GB machine:

  Setting                            Initial value
  -------------------------------- ---------------
  Parser workers                                 3
  Chunk size                                 64 MB
  DuckDB threads                                 3
  Graph workers                                  1
  Queue capacity                      2--4 batches
  DuckDB memory limit                         3 GB
  Application/container hard cap              8 GB

Benchmark 2/3/4 parser workers and 32/64/128 MB chunks on representative
actual data. Do not run parser, DuckDB and graph stages at maximum
concurrency simultaneously.

### 6.3 Backpressure and recovery

Use bounded producer-consumer queues. If the writer falls behind,
parsing must pause rather than accumulating batches in RAM.

Maintain a manifest containing:

-   Source file ID and checksum/size/mtime.
-   Parser version and schema version.
-   Completed byte/record range.
-   Output Parquet files.
-   Record counts by disposition.
-   Completion status.

Resume only from a verified record boundary. Write outputs atomically
(temporary file then rename) so a crash cannot mark a partial Parquet
file as complete.

### 6.4 Parquet layout

-   Use Zstandard compression; benchmark compression level rather than
    assuming the highest level is best.
-   Use typed columns and dictionary encoding for suitable
    low-cardinality fields.
-   Partition initially by date only if it improves the actual query
    patterns.
-   Keep `source_type` as a column unless measured query pruning
    justifies another partition.
-   Compact small chunk outputs into appropriately sized Parquet files.
-   Avoid thousands of tiny files.
-   Keep raw input immutable.

### 6.5 Acceptance tests

-   All source formats in the downloaded data parse.
-   Record-boundary fixture has no lost or duplicated records.
-   Record reconciliation balances.
-   Resume after forced termination works.
-   Raw evidence can be retrieved for a detection.
-   Peak memory is measured for the entire application/container, not
    just DuckDB.

------------------------------------------------------------------------

## 7. FR-2: Detection engine

### 7.1 Detection strategy

Build rules from the actual planted attack steps and available
telemetry.

Create a detection coverage matrix:

  ---------------------------------------------------------------------------
  Planted step   Observable      Rule ID        ATT&CK ID      Test fixture
                 source/fields                                 
  -------------- --------------- -------------- -------------- --------------
  To be filled   To be verified                                
  from ground    from logs                                     
  truth                                                        

  ---------------------------------------------------------------------------

Prioritize:

1.  Rules directly covering planted steps.
2.  Rules connecting two or more planted steps.
3.  Rules that reject benign decoys.
4.  Additional generic security detections.

Start with 10--12 validated rules. Expand toward 25 only if the dataset
and schedule justify it. Rule count is not a success metric; measured
recall, label correctness and false alarms are.

### 7.2 Rule format

Use a constrained YAML format compiled into parameterized SQL. Do not
attempt full Sigma specification compatibility in the hackathon.

Each rule should define:

-   Rule ID and name.
-   Required source/event types.
-   Field predicates.
-   Window/sequence conditions.
-   ATT&CK technique and sub-technique.
-   Severity.
-   Evidence fields.
-   Suppression/deduplication policy.
-   Test fixtures.

Reject unsupported operators at rule-load time. Never concatenate
untrusted values directly into SQL.

### 7.3 Initial rule families

Select only those supported by the actual data:

-   Failed authentication burst followed by success.
-   Suspicious process/script execution.
-   Credential access indicators.
-   Persistence through scheduled task/service creation.
-   Unusual internal host discovery.
-   Remote authentication or execution.
-   Log clearing or defense evasion.
-   Unusual collection/archive activity.
-   Suspicious outbound transfer.
-   Mass file modification/impact.

### 7.4 Behavioural detectors

**First-seen user-to-host:** compare against a defined historical
baseline and consider user/host role and other evidence. Do not flag a
first-seen relationship by itself as a confirmed attack.

**Beaconing:** calculate inter-arrival intervals for repeated outbound
connections and assess regularity, destination and context. A simple
connection count is not enough.

### 7.5 Acceptance

Measure recall and precision on a development split. Keep a separate
validation split for tuning checks. Use the organizer's official
hidden/evaluation data only for final scoring. Ensure no ground-truth
fields are used as detector features.

------------------------------------------------------------------------

## 8. FR-3: MITRE ATT&CK and Cyber Kill Chain

Treat the frameworks as related but distinct.

For each detection:

-   ATT&CK technique/sub-technique comes from the rule and is validated
    against the bundled ATT&CK Enterprise data version.
-   Tactic is retrieved from that ATT&CK data.
-   Cyber Kill Chain stage is assigned using a contextual mapping.
-   Store a confidence and mapping rationale.
-   Use `Unknown` when evidence does not support a reliable stage.

Do not force every ATT&CK tactic into exactly one Kill Chain phase.
Reconnaissance, Defense Evasion, Credential Access and Discovery can
occur at different points in an intrusion.

Suggested output:

``` json
{
  "technique_id": "T1110",
  "sub_technique_id": null,
  "tactic": "Credential Access",
  "kill_chain_stage": "context-dependent",
  "kc_confidence": 0.72,
  "mapping_reason": "derived from observed activity and rule context"
}
```

The value above is illustrative, not a universal mapping for T1110.

Acceptance: all technique IDs exist in the pinned ATT&CK dataset
version; labels are evaluated against the ground-truth matching
contract; unsupported Kill Chain assignments remain unknown rather than
guessed.

------------------------------------------------------------------------

## 9. FR-4: Correlation, incident clustering and attack reconstruction

This is the most important correctness component.

### 9.1 Three distinct operations

**A. Entity resolution**

Determine whether two records refer to the same host, user, process,
session or other entity.

-   Use stable host IDs and source-specific identifiers where available.
-   Normalize usernames carefully (domain, case, realm).
-   Treat IPs as network identifiers, not universal host identities.
-   Use union-find only for high-confidence identity aliases.
-   Keep uncertain aliases as weighted relationships; do not permanently
    merge them.

**B. Evidence correlation**

Determine whether two events are meaningfully related to the same
activity.

Evidence priority:

  -----------------------------------------------------------------------
  Evidence                            Interpretation
  ----------------------------------- -----------------------------------
  Parent/child process relationship   Strong causal evidence

  Same authenticated session          Strong identity/continuity evidence

  Successful remote logon followed by Strong contextual evidence
  activity on that host               

  Host-to-host network connection     Contextual network evidence
  aligned with subsequent activity    

  Same host and compatible time       Supporting evidence

  Same user across hosts              Supporting evidence only

  Shared NAT/proxy/domain-controller  Weak unless corroborated
  IP                                  

  Time proximity alone                Never sufficient to create an
                                      attack edge
  -----------------------------------------------------------------------

Every edge must store `relationship_type`, `confidence`,
`evidence_event_ids` and a short explanation.

**C. Incident clustering**

Generate candidate clusters, then validate/split them. Do not assume
every connected component is one incident: shared service accounts, NAT
addresses and domain controllers can bridge unrelated activity.

Use hub discounting for high-degree entities, but do not rely on it as
the only protection. Add decoy tests for shared-admin, proxy/NAT and
common infrastructure cases.

### 9.2 Correlation score

A weighted score can rank candidate relationships, but it is not
automatically a probability. Calibrate weights against labelled
development data and keep the score named `relationship_score` unless
statistically calibrated.

Temporal proximity may adjust or support a relationship; it must not
create one on its own.

### 9.3 Incident gate

Keep the original incident gate as an initial heuristic, not a universal
truth:

-   Multiple distinct tactics or multiple linked attack steps.
-   At least one strong non-temporal relationship.
-   No unresolved hub-only connection.
-   Evidence and confidence retained.

Allow short genuine incidents to pass when they have strong evidence.
Keep low-confidence activity as unlinked alerts rather than forcing it
into an incident.

### 9.4 Attack path ordering

Do not order the graph solely by event timestamp.

Maintain: - A chronological timeline sorted by normalized event time. -
A directed evidence/causal graph using process lineage, session
continuity and supported cross-host transitions.

For out-of-order events, use event time, ingestion time, timestamp
confidence and known clock offsets. Preserve uncertainty. Do not invent
causal order where none is evidenced.

The attack graph may contain parallel branches and missing stages. It
must not force every incident into a single linear chain.

### 9.5 Evidence model

Each detection and edge should link back to original source records:

``` json
{
  "edge_id": "EDGE_001",
  "source_step": "STEP_001",
  "target_step": "STEP_002",
  "relationship_type": "successful_session_followed_by_host_activity",
  "relationship_score": 0.94,
  "evidence_event_uids": ["EVT_010", "EVT_014"],
  "explanation": "The same session is observed on the destination host."
}
```

Illustrative only. Use the actual available fields.

### 9.6 Acceptance

-   Shared-admin decoy remains separate.
-   Proxy/NAT hub does not merge unrelated incidents.
-   Every edge has evidence and a relationship type.
-   All planted paths are reconstructed in the expected order under the
    scorer.
-   Uncertain steps are marked as uncertain, not silently asserted.

------------------------------------------------------------------------

## 10. FR-5: Timeline and attack graph UI

Build a simple static frontend served by FastAPI. Use Cytoscape.js for
the graph and a lightweight timeline component.

### Incident list

Show: - Incident ID and risk/severity. - First/last observed time. -
Hosts/users involved. - Number of detections and attack steps. -
Confidence and data-quality warnings.

### Incident detail

Show: 1. Chronological event timeline. 2. Attack-step sequence and
ATT&CK/Kill Chain labels. 3. Host/user graph. 4. Evidence drawer for
every step and edge. 5. Data-quality caveats. 6. Observed versus
potential reachability.

Graph rendering cap: limit the number of nodes rendered at once, but do
not truncate the backend's reconstructed incident. Provide filters or
expansion for larger incidents.

Acceptance: an analyst can open an incident and identify its origin,
sequence, involved entities and evidence quickly.

------------------------------------------------------------------------

## 11. FR-6: Reachability analysis

Maintain two distinct concepts.

### Observed

A successful logon/session or connection is evidenced in the logs.

### Potential

A possible access relationship is inferred from available privilege and
network evidence, but no successful session is observed.

Use typed edges:

-   `OBSERVED_SESSION`
-   `NETWORK_REACHABLE`
-   `PRIVILEGE_RELATIONSHIP`

For the hackathon, use bounded 1--2 hop traversal from compromised
hosts/accounts. Include the reason for each result and distinguish
confirmed evidence from assumptions.

Do not claim that administrator membership alone proves a host is
reachable. If firewall/network policy data is absent, state that network
reachability is unknown.

Acceptance: every returned system has an Observed/Potential label, path
and evidence/reason.

------------------------------------------------------------------------

## 12. FR-7: API, persistence and packaging

Use FastAPI with precomputed incident outputs. The incident detail
endpoint should retrieve stored JSON/graph data rather than rebuilding
the graph on every request.

Suggested endpoints:

``` text
POST /run
GET  /status
GET  /incidents
GET  /incidents/{id}
GET  /incidents/{id}/path
GET  /incidents/{id}/reach
GET  /incidents/{id}/report
GET  /data-quality
GET  /bench
GET  /evidence?event_uid=...&ctx=5
```

Use SQLite for small application metadata if needed; keep analytical
event data in Parquet/DuckDB. Avoid introducing another database service
without a demonstrated requirement.

Packaging: - Docker Compose. - Configurable input/output paths. -
Explicit resource limits. - One-command startup. - README tested from a
clean environment. - No external API key required for the core demo. -
Include a small sample mode so judges can verify the application without
processing the full tier.

On Windows, verify the actual Docker Desktop/WSL2 memory limit. Do not
assume container RSS and host process RSS are independent; define the
authoritative memory measurement and avoid double-counting.

------------------------------------------------------------------------

## 13. Data quality and observability

Track metrics by source file, source type and time bucket:

-   Records read.
-   Parsed successfully.
-   Malformed by reason.
-   Duplicate records dropped.
-   Valid records excluded from detection.
-   Eligible records.
-   Missing critical fields.
-   Unknown event types.
-   Inferred timestamps/hosts.
-   Late/out-of-order events.
-   Records rejected by individual rules.

The four terminal dispositions must reconcile exactly. Quality flags are
additional attributes and can overlap.

Expose a dashboard funnel:

`raw records → parsed events → eligible events → detections → attack steps → incidents`

Attach `dq_notes` to incidents where missing or inferred data could make
the path incomplete.

------------------------------------------------------------------------

## 14. Performance architecture and resource budget

Hardware: 16 GB RAM, 8 cores, local-only.

### Initial configuration

  Resource                           Initial setting
  -------------------------------- -----------------
  Application/container hard cap                8 GB
  DuckDB memory limit                           3 GB
  Parser workers                                   3
  DuckDB threads                                   3
  Graph workers                                    1
  Chunk size                                   64 MB
  Queue capacity                        2--4 batches

Benchmark alternative settings on representative actual files. The
configuration is not final until measured.

### Memory measurement

Measure: - Container/cgroup peak memory where applicable. - Process-tree
RSS as a diagnostic. - Host-level memory separately. - Temporary disk
peak.

Do not add overlapping host and container measurements together.

### Disk estimate

Before the full run, measure the actual expansion ratio from a
representative subset:

`required_space = raw_input + normalized_parquet + peak_spill + results + safety_margin`

Do not assume a fixed Parquet compression ratio. Confirm free SSD space
before each tier run. Keep raw logs immutable and clean only
reproducible temporary outputs between runs.

### Benchmark stages

For the 30 GB tier, the Great processing-time target of under one hour requires approximately **8.3 MB/s sustained end-to-end throughput**. Show both the observed throughput and total elapsed time in `/bench`; do not report parser throughput as if it were full-pipeline throughput.

Measure separately: - File read/decompression. - Parsing. -
Normalization. - Parquet writing/compaction. - Detection. - Entity
resolution. - Correlation/clustering. - Graph/reachability. -
Serialization. - End-to-end time.

Optimize the measured bottleneck, not the most visible component.

------------------------------------------------------------------------

## 15. Evaluation and test strategy

### 15.1 Scorer-first

Implement the scorer before tuning rules. It should: - Load ground truth
only in evaluation mode. - Match detections to planted steps using the
organizer's documented keys/tolerance. - Calculate detection recall. -
Calculate ATT&CK label accuracy. - Calculate attack-path reconstruction
and order. - Calculate false-incident rate. - Record runtime and memory.

### 15.2 Test splits

-   Development subset: parser and rule development.
-   Validation subset: tune thresholds and correlation weights.
-   Final full tier: report competition results.

Avoid repeatedly tuning against the same small set until the system
overfits it. Do not use hidden ground truth or ground-truth identifiers
as runtime features.

### 15.3 Test fixtures

Create small deterministic fixtures for: - Failed logins followed by
success. - Process parent/child sequence. - Cross-host movement. -
Shared-admin benign activity. - NAT/proxy hub. - Out-of-order
timestamps. - Duplicate delivery with and without source event IDs. -
Malformed records. - Missing host/user. - Late-arriving events.

Each fixture should have expected detections, edges and incident
grouping.

------------------------------------------------------------------------

## 16. Revised 24-hour schedule for two developers

The schedule must be treated as a parallel plan with hard cut lines. The
complete pipeline should work on a small actual-data subset early; do
not wait until H14 for the first end-to-end run.

  ------------------------------------------------------------------------------------
  Time              Developer A -   Developer B -             Gate
                    Data/detection    Evaluation/correlation/UI   
  ----------------- ----------------- --------------------------- --------------------
  H0--1             Dataset           Ground-truth inspection,    G0: data and scoring
                    inventory,        scorer contract,            contract understood
                    formats, disk     repo/contracts              
                    check                                         

  H1--3             Parser prototype  Scorer skeleton and test    G1: first records
                    on representative fixtures                    parse; scorer loads
                    actual files                                  

  H3--6             Normalization,    Entity model, evidence-edge G2: small end-to-end
                    DQ, Parquet,      model, correlation          pipeline
                    resume            prototype                   

  H6--9             Detection rules   Correlation and incident    G3: detections and
                    for planted steps clustering                  incidents score

  H9--11            ATT&CK validation Path ordering and           G4: P0 pipeline on
                    and Kill Chain    reachability                subset
                    mapping                                       

  H11--14           Ingestion/query   API, incident JSON and      G5: working UI/API
                    tuning            basic graph/timeline        on actual data

  H14--17           Full              Evidence drawer, DQ panel,  G6: full benchmark
                    selected-tier run reachability UI             underway/completed
                    and bottleneck                                
                    fixes                                         

  H17--20           Accuracy and      Packaging, README,          G7: P0/P1 acceptance
                    performance fixes clean-start test            

  H20--22           Final benchmark   Demo rehearsal and backup   G8: results frozen
                    and metric        recording                   
                    capture                                       

  H22--24           Fix only critical Rehearse, verify README and Submission
                    defects           backup                      
  ------------------------------------------------------------------------------------

If the actual full tier takes longer than the available window,
prioritize a correct, reproducible result over adding bonus features. Do
not claim a full-tier benchmark unless it was actually completed.

### Feature cut order

If behind schedule, cut in this order: 1. B-5 live mode. 2. Optional
report polish/LLM. 3. Extra detection rules beyond planted-step
coverage. 4. Optional exports and time-slider replay. 5. Risk-score
sophistication.

Do not cut ingestion correctness, scorer, evidence correlation,
attack-path reconstruction or basic UI/API.

------------------------------------------------------------------------

## 17. Definition of done

### P0

-   [ ] Actual downloaded formats inventoried and supported.
-   [ ] Ground-truth matching contract documented.
-   [ ] Ground truth isolated from runtime engine.
-   [ ] Normalized schema and DQ reconciliation implemented.
-   [ ] Ingestion resumes safely and preserves source evidence.
-   [ ] Selected tier processes under the 8 GB cap.
-   [ ] Detection rules cover the observable planted steps.
-   [ ] ATT&CK IDs validated against pinned dataset version.
-   [ ] Kill Chain mapping supports uncertainty.
-   [ ] Correlation edges have typed evidence.
-   [ ] Shared-admin and hub decoys remain separate.
-   [ ] All planted paths meet scorer requirements.

### P1

-   [ ] Incident list and detail API work.
-   [ ] Timeline and graph render.
-   [ ] Evidence can be opened from a step/edge.
-   [ ] Observed and Potential reachability are distinct.
-   [ ] DQ panel and incident caveats are visible.
-   [ ] One-command Docker startup works from README.
-   [ ] Investigation endpoint meets target latency.

### Competition benchmark

-   [ ] Actual selected tier and exact input files recorded.
-   [ ] End-to-end runtime recorded.
-   [ ] Peak memory measurement method documented.
-   [ ] Peak temporary disk usage recorded.
-   [ ] Detection, label, path and false-alarm metrics reported.
-   [ ] No result is claimed without a completed run.
-   [ ] Demo rehearsed and backup recording ready.

------------------------------------------------------------------------

## 18. Risks and mitigations

  -----------------------------------------------------------------------
  Risk                                Mitigation
  ----------------------------------- -----------------------------------
  Ground-truth format unclear         Resolve matching contract in H0
                                      before rule development

  Actual logs differ from assumed     Dataset-first adapters; no generic
  formats                             framework overbuild

  High false incidents                Separate identity, correlation and
                                      clustering; hub/decoy tests

  Incorrect attack ordering           Causal graph plus timestamp-aware
                                      timeline

  Memory exceeds 8 GB                 Bounded queues, staged processing,
                                      container limit, RSS/cgroup
                                      monitoring

  Disk fills                          Measure actual expansion ratio;
                                      verify free space; compact Parquet

  Parsing bottleneck                  Benchmark file-level parallelism
                                      and chunk size

  Correlation bottleneck              Index candidate entities/time
                                      ranges; avoid all-pairs joins

  Graph too large                     Aggregate to attack steps; cap UI
                                      rendering only

  Judges cannot run it                Offline-capable Docker Compose and
                                      clean-machine README test

  Accuracy tuning overfits            Separate development/validation
                                      data and preserve final evaluation
  -----------------------------------------------------------------------

------------------------------------------------------------------------

## 19. Final recommendation

Freeze this scope:

**Must build:** dataset-specific ingestion, normalization, data-quality
accounting, detection, ATT&CK/Kill Chain classification, evidence-based
correlation, incident separation, attack-path reconstruction,
observed/potential reachability, API and simple graph/timeline UI.

**Only after that works:** risk ranking, deterministic reports, alert
aggregation, config-rule demo and live mode.

The differentiator is not the number of rules, the use of AI, or the
complexity of the dashboard. It is the ability to take large volumes of
raw logs and produce a coherent, correctly ordered, evidence-backed
attack story while staying within the memory and runtime limits.

### Immediate next action

Run the dataset inventory and ground-truth inspection before coding the
adapters. Record the actual file formats, schemas, field coverage,
attack-step identifiers and disk expansion ratio. Use those findings to
fill the detection coverage matrix and finalize the parser plan.
