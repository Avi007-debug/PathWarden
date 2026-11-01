// PathWarden Core Domain and API Data Types
// Compliant with PathWarden (formerly ChainSight) v5.1 specification

export type TerminalDisposition =
  | "MALFORMED"
  | "DUPLICATE_DROPPED"
  | "VALID_EXCLUDED"
  | "ELIGIBLE";

export type ParseStatus =
  | "PARSED"
  | "PARTIAL"
  | "MALFORMED"
  | "UNSUPPORTED_FORMAT"
  | "UNCLASSIFIED";

export type EventOutcome = "SUCCESS" | "FAILURE" | "UNKNOWN";

export type EvidenceStatus = "OBSERVED" | "INFERRED" | "POTENTIAL";

export type EntityType =
  | "host"
  | "user"
  | "process"
  | "ip"
  | "domain"
  | "file"
  | "session";

export interface CanonicalEvent {
  event_uid: string;
  source_event_id: string | null;
  event_ts: string | null;
  event_ts_original: string | null;
  ingest_ts: string;
  source_type: string;
  sensor_id: string | null;
  event_category: string | null;
  event_type: string | null;
  action: string | null;
  outcome: EventOutcome | null;
  host_id: string | null;
  host_name: string | null;
  user_id: string | null;
  user_name: string | null;
  src_ip: string | null;
  src_port: number | null;
  dst_ip: string | null;
  dst_port: number | null;
  network_protocol: string | null;
  process_id: string | null;
  parent_process_id: string | null;
  process_entity_id: string | null;
  session_id: string | null;
  raw_event_reference: string;
  parse_status: ParseStatus;
  dq_flags: string[];
  extra: Record<string, unknown>;
}

export interface DetectionRecord {
  detection_id: string;
  rule_id: string;
  rule_name: string;
  rule_version: string;
  event_uids: string[];
  primary_event_uid: string | null;
  detected_at: string;
  severity: "INFO" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL" | "UNKNOWN";
  confidence: number | null;
  description: string;
  evidence: Record<string, unknown> | unknown[];
  mitre_technique_id: string | null;
  mitre_technique_name: string | null;
  mitre_tactic: string | null;
  kill_chain_stage: string;
  kc_confidence: number | string;
  mapping_reason: string;
}

export interface GraphRelationship {
  relationship_id: string;
  incident_id: string;
  entity_id: string;
  entity_type: EntityType;
  source_entity_id: string;
  target_entity_id: string;
  relationship_type: string;
  relationship_score: number;
  relationship_confidence?: number | string | null;
  evidence_event_uids: string[];
  explanation: string;
  observed_or_inferred: EvidenceStatus;
  first_seen_ts: string | null;
  last_seen_ts: string | null;
}

export type DataQualityFlag =
  | "HOST_INFERRED"
  | "TIMESTAMP_UNCERTAIN"
  | "UNKNOWN_EVENT_TYPE"
  | "CLOCK_SKEW_DETECTED"
  | "LATE_ARRIVING"
  | "TRUNCATED_RECORD"
  | "MISSING_CRITICAL_FIELD";

export type IncidentSeverity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFORMATIONAL";

export type KillChainStage =
  | "Reconnaissance"
  | "Weaponization"
  | "Delivery"
  | "Exploitation"
  | "Installation"
  | "Command and Control"
  | "Actions on Objectives"
  | "Initial Access"
  | "Execution"
  | "Persistence"
  | "Privilege Escalation"
  | "Defense Evasion"
  | "Credential Access"
  | "Discovery"
  | "Lateral Movement"
  | "Collection"
  | "Exfiltration"
  | "Impact"
  | "Unknown";

export interface MitreAttackRef {
  tactic: string;
  technique_id: string;
  technique_name: string;
  sub_technique_id?: string | null;
}

export interface NetworkThreatInfo {
  destination_ip?: string | null;
  destination_port?: number | null;
  destination_domain?: string | null;
  network_protocol?: string | null;
  threat_category?: string | null;
  threat_confidence?: number | null;
  direction?: "OUTBOUND" | "INBOUND" | "LATERAL" | string | null;
  command_snippet?: string | null;
}

export interface FPVerification {
  verdict: "CONFIRMED_MALICIOUS_ATTACK" | "BENIGN_ADMIN_ACTIVITY" | "SUSPICIOUS_UNVERIFIED";
  attack_confidence: number;
  false_positive_risk: number;
  corroboration_score: number;
  is_admin_tool_signature: boolean;
  objective_achieved: boolean;
  multi_stage_depth: number;
  explanation_points: string[];
}

export interface AttackStep {
  step_uid: string;
  incident_id: string;
  order_index: number;
  timestamp: string;
  host_id?: string | null;
  host_name: string;
  user_id?: string | null;
  user_name: string;
  process_id?: number | null;
  process_name?: string | null;
  parent_process_name?: string | null;
  command_line?: string | null;
  mitre: MitreAttackRef;
  kill_chain_stage: KillChainStage;
  kc_confidence: number;
  severity: IncidentSeverity;
  detection_confidence: number;
  rule_id: string;
  rule_name: string;
  explanation: string;
  evidence_event_uids: string[];
  is_uncertain?: boolean;
  dq_flags?: DataQualityFlag[];
  network_threat?: NetworkThreatInfo | null;
}

export type EdgeRelationshipType =
  | "parent_child_process"
  | "same_authenticated_session"
  | "successful_session_followed_by_host_activity"
  | "host_to_host_network_connection"
  | "remote_authentication"
  | "suspicious_script_launch"
  | "lateral_movement"
  | "persistence_trigger"
  | "credential_reuse"
  | "command_sequence"
  | "process_lineage"
  | "authentication_recovery";

export interface AttackEdge {
  edge_id: string;
  incident_id: string;
  source_step_uid: string;
  target_step_uid: string;
  relationship_type: EdgeRelationshipType;
  relationship_score: number; // 0.0 - 1.0 calibrated score
  confidence_category: "STRONG" | "MODERATE" | "UNCERTAIN";
  evidence_event_uids: string[];
  explanation: string;
  is_inferred: boolean;
  latency_seconds?: number;
}

export interface IncidentDataQualityCaveat {
  type: DataQualityFlag;
  severity: "WARNING" | "INFO";
  affected_steps: string[];
  description: string;
}

export interface Incident {
  incident_id: string;
  title: string;
  severity: IncidentSeverity;
  risk_score?: number; // Bonus B-1: 0 - 100 risk score
  confidence: number; // 0.0 - 1.0
  first_seen: string;
  last_seen: string;
  hosts_involved: string[];
  users_involved: string[];
  root_cause_host?: string;
  root_cause_user?: string;
  steps_count: number;
  detection_count: number;
  tactics: string[];
  status: "ACTIVE_INVESTIGATION" | "CONTAINED" | "RESOLVED" | "VERIFIED_ATTACK";
  dq_caveats: IncidentDataQualityCaveat[];
  summary: string;
  plain_english_report?: string; // Bonus B-2: Executive plain English narrative
  executive_report_markdown?: string; // Bonus B-2: Full multi-agent markdown report
  report_engine_used?: string; // Bonus B-2: On-Device LLM or Agentic Engine
  raw_alerts_merged?: number; // Bonus B-3: Raw alerts/detections merged into this incident
  alert_compression_pct?: number; // Bonus B-3: Noise reduction percentage
  planted_attack_id?: string;
  is_planted_match?: boolean;
  fp_verification?: FPVerification | null;
}

export interface ExecutiveReportResponse {
  incident_id: string;
  severity: string;
  risk_score: number;
  plain_english_report: string;
  report_markdown: string;
  raw_alerts_merged: number;
  alert_compression_pct: number;
  engine_used: string;
  generated_at: string;
  agent_workflow: {
    analyst_agent: string;
    forensics_agent: string;
    executive_reporter_agent: string;
  };
}

export interface IncidentDetail extends Incident {
  steps: AttackStep[];
  edges: AttackEdge[];
}

export type ReachabilityRelationshipType =
  | "OBSERVED_SESSION"
  | "NETWORK_REACHABLE"
  | "PRIVILEGE_RELATIONSHIP";

export interface ReachabilityItem {
  id: string;
  incident_id: string;
  source_entity: string;
  source_type: "HOST" | "USER" | "PROCESS";
  target_entity: string;
  target_type: "HOST" | "DATABASE" | "DOMAIN_CONTROLLER" | "BACKUP_SERVER" | "FILE_SHARE" | "CRITICAL_ASSET";
  relationship_type: ReachabilityRelationshipType;
  hops: number;
  confidence: number;
  evidence_event_uids: string[];
  rationale: string;
  network_policy_known: boolean;
  privilege_level?: string;
  assumptions: string[];
  last_observed_ts?: string;
}

export interface DataQualitySourceMetric {
  source_name: string;
  source_type: string;
  records_read: number;
  malformed: number;
  duplicate_dropped: number;
  valid_excluded: number;
  eligible: number;
  parse_success_rate_pct: number;
  inferred_hosts_count: number;
  inferred_ts_count: number;
  unknown_events_count: number;
}

export interface DataQualityReport {
  workspace: string;
  tier: string;
  timestamp: string;
  total_records_read: number;
  malformed_count: number;
  malformed_reasons: Record<string, number>;
  duplicate_dropped_count: number;
  valid_excluded_count: number;
  eligible_count: number;
  reconciliation_balanced: boolean; // records_read === malformed + duplicate + excluded + eligible
  total_detections: number;
  total_attack_steps: number;
  total_incidents: number;
  flags_summary: Record<DataQualityFlag, number>;
  sources: DataQualitySourceMetric[];
}

export interface BenchmarkStageMetric {
  stage_name: string;
  target_seconds: number;
  measured_seconds: number;
  target_throughput_mbs?: number;
  measured_throughput_mbs?: number;
  status: "EXCEEDED_TARGET" | "MET_TARGET" | "NOT_MET" | "PENDING";
}

export interface BenchmarkReport {
  tier_name: string;
  dataset_size_gb: number;
  multiplier: string;
  target_hardware: {
    cores: number;
    ram_gb: number;
    container_cap_gb: number;
  };
  total_duration_seconds: number;
  target_duration_seconds: number;
  peak_container_memory_mb: number;
  target_memory_mb: number;
  peak_temp_disk_mb: number;
  sustained_throughput_mbs: number;
  target_throughput_mbs: number;
  investigation_latency_ms: number;
  target_latency_ms: number;
  metrics: {
    detection_recall_pct: number;
    target_recall_pct: number;
    label_accuracy_pct: number;
    target_label_accuracy_pct: number;
    path_reconstruction_pct: number;
    target_path_reconstruction_pct: number;
    false_alarm_rate_pct: number;
    target_false_alarm_pct: number;
  };
  stages: BenchmarkStageMetric[];
  status: "COMPLETED" | "RUNNING" | "BENCHMARK_PENDING";
  last_run_timestamp: string;
}

export interface RawEvidenceRecord {
  event_uid: string;
  source_file_id: string;
  source_type: string;
  event_ts: string;
  ingest_ts: string;
  timestamp_precision: string;
  timestamp_confidence: number;
  event_type: string;
  action: string;
  outcome: string;
  host_id?: string | null;
  host_name?: string | null;
  user_id?: string | null;
  user_name?: string | null;
  src_ip?: string | null;
  src_port?: number | null;
  dst_ip?: string | null;
  dst_port?: number | null;
  protocol?: string | null;
  process_id?: number | null;
  process_name?: string | null;
  parent_process_id?: number | null;
  parent_process_name?: string | null;
  command_line?: string | null;
  session_id?: string | null;
  record_id?: string | null;
  parse_status: "valid" | "malformed" | "duplicate";
  host_inferred: boolean;
  ts_inferred: boolean;
  is_late: boolean;
  dq_flags: DataQualityFlag[];
  raw_log_snippet: string;
  extra?: Record<string, unknown>;
}

export interface RunAnalysisRequest {
  dataset_path: string;
  tier: "CORE_15GB" | "ADVANCED_30GB" | "EXTREME_50GB";
  duckdb_memory_limit_gb: number;
  parser_workers: number;
  max_container_memory_gb: number;
}

export interface RunAnalysisResponse {
  run_id: string;
  status: "QUEUED" | "RUNNING" | "COMPLETED" | "FAILED";
  message: string;
  started_at: string;
  events_processed?: number;
  detections_extracted?: number;
  incidents_count?: number;
}

export interface MachineSpecifications {
  cpu_cores: number;
  total_ram_gb: number;
  used_ram_gb: number;
  free_ram_gb: number;
  process_memory_mb: number;
  platform: string;
  budget_limit_gb: number;
  storage_engine: string;
}

export interface CompetitionTargetItem {
  id: string;
  measure: string;
  how: string;
  good: string;
  great: string;
  actual: string;
  status: "Great" | "Good" | "Needs Improvement";
  passing: boolean;
}

export interface ProcessingStatusResponse {
  run_id: string;
  status: "IDLE" | "PARSING" | "NORMALIZING" | "DETECTING" | "CORRELATING" | "RECONSTRUCTING" | "COMPLETED" | "FAILED";
  current_stage: string;
  current_file?: string;
  progress_pct: number;
  elapsed_seconds: number;
  records_processed: number;
  eligible_events_found: number;
  detections_count: number;
  incidents_count: number;
  peak_memory_mb: number;
  error_message?: string | null;
  memory_used_gb?: number;
  memory_budget_gb?: number;
  memory_usage_pct?: number;
  cpu_usage_pct?: number;
  storage_engine?: string;
  engine_mode?: string;
  tier_name?: string;
  dataset_size_gb?: number;
  machine_specifications?: MachineSpecifications;
  target_matrix?: CompetitionTargetItem[];
}

export interface DetectionRule {
  rule_id: string;
  rule_name: string;
  rule_version?: string;
  technique_id: string;
  technique_name: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | string;
  tactic: string;
  description: string;
  query: string;
}

export interface RulesResponse {
  rules_count: number;
  config_path: string;
  rules: DetectionRule[];
}

