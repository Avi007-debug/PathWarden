# PathWarden Scalability Implementation Plan

> **Scope:** Practical scalability improvements for FR-1 through FR-7 that can be implemented within a 12-hour development window.
>
> **Principle:** Prioritize bounded resource usage, incremental processing, evidence correctness, recoverability, and bounded API/UI responses. Avoid introducing distributed infrastructure unless it already exists.

## 1. Goals and Non-Goals

### Goals
- Process large log datasets without loading the entire dataset into application memory.
- Use columnar storage and analytical queries for detection.
- Enrich detections without repeatedly loading or fetching mapping metadata.
- Correlate events across input batches and preserve supporting evidence.
- Keep incident timelines, attack graphs, and reachability responses bounded.
- Run long-running work outside synchronous API requests and support safe recovery.
- Measure actual performance instead of claiming a dataset-size guarantee without testing.

### Defer for the 12-hour window
- Distributed processing/orchestration platforms.
- A graph database migration solely for scalability.
- Exhaustive graph-wide pathfinding.
- Parallel execution of every rule or parser task before resource use is measured.
- Live synchronization of threat-mapping data.
- Support for every possible log source or format.

## 2. Recommended Architecture

```text
Large log files
    |
    v
FR-1: Streaming / chunked ingestion
    |  bounded buffers, validation, checkpoints
    v
Normalized events in Parquet
    |
    v
FR-2: DuckDB analytical detection
    |  selected columns, selective filters, rule metrics
    v
FR-3: Local ATT&CK / Kill Chain enrichment
    |  preloaded indexed mappings, batch enrichment
    v
FR-4: Incremental evidence correlation
    |  indexed candidates, cross-batch matching
    v
Persisted incidents, entities, and evidence-backed graph edges
    |                                  |
    v                                  v
FR-5: Incident-scoped UI             FR-6: Bounded reachability
    |  paginated timeline              |  indexed traversal
    |  lazy evidence details           |  cycle and result limits
    +------------------+---------------+
                       |
                       v
FR-7: API + separate worker + persistent job state
       checkpoints, idempotent writes, status, runbook
```

### Recommended implementation choices

| Concern | Choice |
|---|---|
| Ingestion | Python streaming/chunk-based processing |
| Normalized event storage | Parquet |
| Analytical queries | DuckDB querying Parquet |
| Detection rules | Existing rule format; YAML if not already established |
| ATT&CK / Kill Chain mappings | Local, version-pinned files and in-memory dictionaries |
| API | Keep the existing API framework; use FastAPI if already in the backend |
| Long-running processing | One dedicated worker initially |
| Job / incident / graph metadata | Existing database and schema where practical |
| Frontend | Server-side filtering and pagination; bounded incident graph responses |

Use the current repository and its existing data model as the source of truth. These recommendations do not imply that a feature is already implemented.

## 3. Five Core Engineering Decisions

1. **Never load the complete dataset into Python memory.** Stream or batch input, keep buffers bounded, and write results incrementally.
2. **Use Parquet and DuckDB for analytical processing.** Query only the needed columns and rows; avoid materializing the full dataset in Python.
3. **Make correlation incremental and cross-batch aware.** Use indexed candidate generation and persist relevant entity/correlation state so events from different batches can still be linked.
4. **Persist relationships and serve bounded, incident-scoped results.** Do not rebuild the entire graph for every UI request or send the complete dataset to the browser.
5. **Run heavy processing through a recoverable worker.** Persist job state and checkpoints, and make retries safe against duplicate committed outputs.

## 4. Functional Requirement Implementation

## FR-1 — Log Ingestion, Parsing and Normalisation

**Approach:** Data-level scalability.

### Must implement
- **Streaming/chunked ingestion:** Read input incrementally. Start with a configurable 64 MB chunk/read-buffer target where appropriate, then benchmark it.
- **Bounded memory:** Limit in-flight batches and avoid accumulating all parsed events in a Python list.
- **Parquet output:** Write normalized events incrementally in batches.
- **Checkpointing:** Persist the input identifier, last safely committed offset/batch, and processing status.
- **Modular adapters:** Keep source-specific parsing separate from the canonical normalized-event schema.

### Implementation notes
1. Read a bounded portion of the input.
2. Parse and normalize records in that portion.
3. Write the completed batch to Parquet.
4. Commit output and checkpoint safely.
5. Repeat until input is processed.
6. Record malformed records and continue only when the error is recoverable.

A 64 MB chunk target is not a guarantee of 64 MB total memory use. Parsing, decompression, object allocation, and output buffers add overhead. For compressed formats, use format-aware streaming rather than assuming compressed file offsets can be resumed directly.

### Defer
- Multiprocessing until single-worker memory and throughput are measured.
- Additional log adapters not required for the current demo.

### Acceptance checks
- Large input is processed incrementally.
- Memory use remains bounded in a representative test.
- Normalized output is written in batches.
- An interrupted run can resume from a safe checkpoint without duplicating committed records.

## FR-2 — Rule-Based Detection Engine

**Approach:** Query-level and rule-level scalability.

### Must implement
- **DuckDB over Parquet:** Run detection queries directly against stored Parquet data.
- **Column selection:** Read only the fields needed by each rule.
- **Selective filters:** Apply relevant event-type, time, host, or other filters early where consistent with rule semantics.
- **Modular rules:** Keep rules independently defined using the existing format; use YAML if no rule format exists.
- **Execution metrics:** Record each rule's duration, status, and finding count.

### Implementation notes
- Avoid creating a full in-memory dataframe of the entire dataset.
- Prefer filtering and aggregation in DuckDB over loading raw records into Python.
- Use partition pruning only when the partition layout and query filters support it; avoid excessive tiny partitions.
- Execute rules sequentially at first. Measure resource usage before adding concurrency.
- Preserve each rule's detection semantics while optimizing its query.

### Defer
- Parallel rule execution.
- Complex query scheduling or a custom query optimizer.

### Acceptance checks
- At least two representative rules run against Parquet-backed data.
- Expected findings are produced.
- Rule-level timing and result counts are recorded.
- The full dataset is not materialized in Python for each rule.

## FR-3 — MITRE ATT&CK and Cyber Kill Chain Mapping

**Approach:** Metadata-level and lookup scalability.

### Must implement
- **Local mapping data:** Use a locally stored, version-pinned ATT&CK dataset containing the techniques required by the demo.
- **Predefined mappings:** Store technique and Kill Chain mappings in configuration files.
- **Indexed lookup:** Build dictionaries keyed by stable technique IDs.
- **Mapping reuse:** Load and validate mappings once per worker process and reuse them.
- **Batch enrichment:** Enrich batches of detections rather than reloading metadata per detection.
- **Version tracking:** Record the dataset and mapping-configuration versions used for a job or result set.

### Implementation notes
- Validate mapping references at startup.
- Handle unknown or invalid technique IDs without failing the entire batch.
- Do not make a network request for every detection.
- Keep the mapping source/version traceable for reproducibility.

### Defer
- Live mapping synchronization service.

### Acceptance checks
- A batch containing repeated technique IDs is enriched using the preloaded lookup.
- Unknown technique IDs are handled safely.
- The mapping version is recorded.

## FR-4 — Evidence Correlation, Incident Clustering and Attack-Path Reconstruction

**Approach:** Indexed candidate generation and incremental graph construction.

### Must implement
- **Indexed candidate generation:** Generate candidates using relevant identifiers such as host, user, process, session, or other fields actually available in the event schema.
- **Time-window filtering:** Apply relationship-appropriate time windows where relevant.
- **Cross-batch correlation:** Preserve entity and correlation state so events processed in different batches can still be linked.
- **Stable entity IDs:** Use consistent identifiers across batches.
- **Persisted graph edges:** Store relationships separately with stable IDs.
- **Evidence references:** Preserve source event/evidence IDs and relevant timestamps for each relationship.
- **Hub safeguards:** Do not merge incidents solely because they share a common administrator, server, or other high-degree entity.

### Implementation notes
- Avoid all-pairs comparisons between events.
- Use indexed candidate generation to reduce the comparison set.
- Keep entity resolution consistent across batches.
- Handle out-of-order or late events with a documented policy. A simple bounded lateness policy is acceptable for the first version if its limitations are explicit.
- Store edge type, source entity, destination entity, evidence references, and any confidence/qualification fields actually supported by the implementation.
- Require additional context before merging clusters through common accounts or infrastructure.

### Defer
- Graph database migration.
- Distributed graph processing and advanced global graph optimization.

### Acceptance checks
- Related events split across batches can still be correlated.
- Graph edges retain evidence references.
- Shared accounts or common servers do not automatically merge unrelated incidents.
- Correlation avoids a naive all-pairs comparison.

## FR-5 — Incident Timeline and Attack Graph UI

**Approach:** Server-side pagination and incident-scoped rendering.

### Must implement
- **Server-side pagination:** Use bounded pages or cursor-based pagination for timeline records.
- **Incident-scoped queries:** Fetch only the selected incident's summary, timeline, and graph subset.
- **Server-side filtering:** Filter supported time, event-type, severity, or other relevant fields at the backend.
- **Lazy evidence details:** Fetch detailed evidence only when an analyst opens a record.
- **Bounded graph response:** Limit the initial graph to the selected incident and support controlled expansion only if time permits.
- **Loading and error states:** Distinguish loading, empty results, and failed requests.

### Implementation notes
- Never send the complete log dataset to the browser.
- Return incident summaries instead of every underlying event in the incident list.
- Cancel obsolete requests when the selected incident or filters change.
- Apply suitable limits to page sizes and graph response sizes.

### Defer
- Complex graph visualization features.
- Extensive list virtualization unless actual UI performance requires it.

### Acceptance checks
- Initial incident and timeline requests return bounded results.
- Additional timeline data can be fetched on demand.
- Evidence details load only when requested.
- The browser does not attempt to render the entire dataset.

## FR-6 — Observed and Potential Reachability

**Approach:** Indexed graph traversal with strict bounds.

### Must implement
- **Persisted relationships:** Query graph relationships created by FR-4 instead of rescanning raw logs per request.
- **Bounded traversal:** Start with a configurable maximum of one or two hops for the demo.
- **Indexed adjacency lookups:** Index relationships by source entity and relevant lookup fields.
- **Cycle detection:** Maintain a visited set.
- **Result limits:** Bound nodes, edges, execution time, and response size.
- **Explicit semantics:** Distinguish `OBSERVED`, `POTENTIAL`, and `UNKNOWN` according to evidence and implemented rules.

### Reachability semantics
- **OBSERVED:** Directly supported by evidence meeting the implementation's criteria.
- **POTENTIAL:** A plausible relationship inferred from available topology or other supporting information, but not established as an observed connection.
- **UNKNOWN:** Evidence is insufficient to determine the relationship.

Do not label a potential path as a confirmed attack path. Ensure the labels match the actual evidence model.

### Defer
- Exhaustive graph-wide pathfinding and advanced path ranking.

### Acceptance checks
- Traversal terminates on graphs containing cycles.
- Configured hop and result limits are enforced.
- Results include relevant evidence references and correctly qualified reachability labels.

## FR-7 — API, Persistence, Packaging and Runbook

**Approach:** Asynchronous processing, persistent job state, and recoverability.

### Must implement
- **Separate worker:** Run long-running ingestion and analysis outside synchronous API request handling.
- **Persistent job registry:** Store job ID, input reference, status, timestamps, and progress where measurable.
- **Checkpoint-based recovery:** Resume from the last successfully committed batch.
- **Idempotent writes:** Use stable identifiers and uniqueness constraints or equivalent safeguards to prevent duplicate committed results after retries.
- **Job-status API:** Expose status, progress, and error information.
- **Resource limits:** Configure bounded worker concurrency, query timeouts, and suitable input limits.
- **Startup instructions:** Document environment configuration, startup commands, sample data, and known limitations.

### Suggested job states
- `QUEUED`
- `RUNNING`
- `COMPLETED`
- `COMPLETED_WITH_ERRORS`
- `FAILED`
- `CANCELLED` — only if safe cancellation is implemented.

Use the existing project's status model if one already exists; avoid unnecessary API incompatibility.

### Implementation notes
- Return a job ID promptly rather than holding the request open for the full processing run.
- Persist job state and checkpoints so a worker restart does not erase progress.
- A background task tied only to a short-lived API process is not sufficient for recoverable long-running work.
- Keep the first version to one worker unless measurements or existing infrastructure justify more concurrency.

### Defer
- Distributed queues and Kubernetes unless already present or required by the existing architecture.

### Acceptance checks
- A job can be submitted and its status queried.
- Progress and errors are visible.
- A worker interruption can be recovered from a safe checkpoint.
- Retrying does not duplicate committed outputs.
- Startup instructions reproduce the demo environment.

## 5. Cross-Feature Data and API Principles

- Use stable IDs for jobs, events, detections, entities, incidents, and graph edges.
- Preserve lineage from a detection or graph edge back to supporting source evidence.
- Apply pagination, timeouts, and result-size limits to potentially large queries.
- Make processing stages observable through status, counters, timings, and structured errors.
- Keep processing version information so results can be interpreted and reproduced.
- Distinguish an empty result from a failed or incomplete query.
- Avoid schema changes that break existing API clients; extend existing contracts where possible.
- Keep the actual repository schema and existing implementation authoritative.

## 6. 12-Hour Implementation Schedule

This schedule assumes the repository and basic application already exist. Reuse existing working components instead of rewriting them.

| Time | Task | Expected result |
|---|---|---|
| Hour 1 | Audit current implementation, data schema, and baseline behavior | Identify gaps and preserve working code |
| Hours 2–3 | Implement bounded ingestion, Parquet output, and safe checkpointing | FR-1 incremental pipeline |
| Hour 4 | Integrate DuckDB queries, rule filters, and execution metrics | FR-2 analytical detection |
| Hour 5 | Load local mappings once and implement batch enrichment | FR-3 efficient enrichment |
| Hours 6–7 | Implement indexed candidate generation, cross-batch matching, and persisted evidence-backed edges | FR-4 incident graph |
| Hour 8 | Implement incident-scoped API responses, timeline pagination, and lazy evidence | FR-5 bounded UI data |
| Hour 9 | Implement indexed bounded reachability and cycle/result limits | FR-6 controlled traversal |
| Hour 10 | Connect the separate worker, persistent job status, and retry-safe writes | FR-7 recoverable jobs |
| Hour 11 | Run end-to-end, failure/recovery, and cross-batch integration tests | Verified pipeline on representative data |
| Hour 12 | Benchmark, fix critical defects, document limitations, and prepare demo | Reproducible demonstration |

If the current application lacks a working end-to-end path, prioritize functional integration over optional optimizations. Do not spend the full window polishing isolated components that are not connected.

## 7. Validation and Benchmarking

A 30 GB input target must be validated with representative data; the architecture alone does not guarantee a specific processing time.

### Suggested progression
1. Small representative sample — functional correctness.
2. Approximately 1 GB — pipeline and memory behavior.
3. Approximately 5 GB — emerging bottlenecks.
4. Approximately 10 GB, if time permits — larger-scale behavior.
5. Full 30 GB, if time and hardware permit — end-to-end validation.

### Record these metrics
- Input size and record count.
- Ingestion throughput and peak memory.
- Parse errors and skipped-record count.
- Parquet output size and total disk usage.
- Per-rule duration and finding count.
- Correlation duration and graph entity/edge counts.
- Incident summary and paginated timeline response latency.
- Reachability traversal duration and result size.
- Recovery correctness after a controlled interruption.

The proposed test sizes are milestones, not completion-time guarantees. Leave disk headroom for normalized data, indexes, graph data, temporary spill, and retained source files.

## 8. Final Priority Matrix

| FR | Must-have implementation | Defer until later |
|---|---|---|
| **FR-1** | Streaming/chunked ingestion, bounded memory, Parquet output, checkpoints | Multiprocessing and many additional log adapters |
| **FR-2** | DuckDB queries over Parquet, column selection, filters, modular rules, execution metrics | Parallel rule execution and complex query scheduling |
| **FR-3** | Local ATT&CK mappings, indexed lookups, batch enrichment, version tracking | Live synchronization service |
| **FR-4** | Indexed candidate generation, cross-batch correlation, persisted graph edges, evidence references | Graph database migration and advanced graph optimization |
| **FR-5** | Server-side pagination, incident-scoped data, lazy evidence loading, bounded graph | Complex graph visualization and extensive UI virtualization |
| **FR-6** | Indexed relationships, bounded traversal, cycle detection, result limits, explicit reachability semantics | Exhaustive graph-wide pathfinding |
| **FR-7** | Separate worker, persistent job status, checkpoints, idempotent writes, startup instructions | Distributed task infrastructure and Kubernetes |

## 9. Definition of Done

- [ ] Large input is processed incrementally without loading the complete dataset into application memory.
- [ ] Normalized events are persisted to Parquet and queried through DuckDB where appropriate.
- [ ] Detection rules produce expected findings and expose execution metrics.
- [ ] ATT&CK / Kill Chain mappings are loaded locally, reused, and versioned.
- [ ] Correlation works across batches and graph edges preserve evidence references.
- [ ] Incident timelines and graphs are fetched as bounded, incident-scoped responses.
- [ ] Reachability traversal respects hop, cycle, time, and result limits.
- [ ] Long-running jobs expose persistent status and can recover from safe checkpoints.
- [ ] Retries do not duplicate committed outputs.
- [ ] Benchmark results and known limitations are documented.

**Final principle:** Build a correct, incremental, recoverable, and bounded pipeline first. Optimize concurrency or add distributed infrastructure only when benchmark results justify it.
