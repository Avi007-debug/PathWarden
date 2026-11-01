// PathWarden API Client
// Provides strongly-typed HTTP calls to the PathWarden FastAPI backend with clean Demo Mode support

import {
  Incident,
  IncidentDetail,
  ReachabilityItem,
  DataQualityReport,
  BenchmarkReport,
  RawEvidenceRecord,
  ProcessingStatusResponse,
  RunAnalysisRequest,
  RunAnalysisResponse,
  DetectionRule,
  RulesResponse,
  ExecutiveReportResponse,
} from "./types";
import {
  DEMO_INCIDENTS,
  DEMO_INCIDENT_DETAIL,
  DEMO_INCIDENT_GRAPHS,
  DEMO_REACHABILITY_ITEMS,
  DEMO_DATA_QUALITY_REPORT,
  DEMO_BENCHMARK_REPORT,
  DEMO_PROCESSING_STATUS,
  DEMO_RAW_EVIDENCE_MAP,
} from "../demo/syntheticData";

export const getApiBaseUrl = (): string => {
  if (typeof window !== "undefined") {
    try {
      const params = new URLSearchParams(window.location.search);
      const urlParam = params.get("api") || params.get("backend");
      if (urlParam) {
        localStorage.setItem("pathwarden_custom_api_url", urlParam);
        return urlParam.replace(/\/$/, "");
      }
    } catch {
      // Ignored
    }
    const customUrl = localStorage.getItem("pathwarden_custom_api_url");
    if (customUrl) return customUrl.replace(/\/$/, "");
  }
  if (process.env.NEXT_PUBLIC_API_BASE_URL) return process.env.NEXT_PUBLIC_API_BASE_URL;
  if (process.env.NEXT_PUBLIC_API_URL) return process.env.NEXT_PUBLIC_API_URL;
  // Default to local backend on port 8000 so deployed frontend connects to local backend
  return "http://localhost:8000";
};

export class ApiError extends Error {
  constructor(
    public status: number,
    public statusText: string,
    public endpoint: string,
    public detail?: string
  ) {
    super(`API Error ${status} (${statusText}) at ${endpoint}: ${detail || "Request failed"}`);
    this.name = "ApiError";
  }
}

async function request<T>(
  endpoint: string,
  options?: RequestInit,
  isDemoMode: boolean = false
): Promise<T> {
  const baseUrl = getApiBaseUrl();

  // If explicitly in Demo Mode or if on cloud hosting without an external backend, return synthetic fixtures
  if (isDemoMode || !baseUrl) {
    return getSyntheticResponse<T>(endpoint);
  }

  const url = `${baseUrl}${endpoint}`;
  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 10000); // 10s timeout

    const res = await fetch(url, {
      ...options,
      signal: controller.signal,
      headers: {
        "Content-Type": "application/json",
        Accept: "application/json",
        "ngrok-skip-browser-warning": "true",
        "Bypass-Tunnel-Reminder": "true",
        ...(options?.headers || {}),
      },
    });

    clearTimeout(timeoutId);

    if (!res.ok) {
      let detail = "";
      try {
        const errJson = await res.json();
        detail = errJson.detail || errJson.message || "";
      } catch {
        // response was not JSON
      }
      throw new ApiError(res.status, res.statusText, endpoint, detail);
    }

    return (await res.json()) as T;
  } catch (err: unknown) {
    if (err instanceof ApiError) {
      throw err;
    }
    const error = err as Error;
    throw new ApiError(0, error.name || "NetworkError", endpoint, error.message || "Failed to reach backend");
  }
}

function getSyntheticResponse<T>(endpoint: string): T {
  if (endpoint === "/status") {
    return DEMO_PROCESSING_STATUS as unknown as T;
  }
  if (endpoint === "/incidents") {
    return DEMO_INCIDENTS as unknown as T;
  }
  if (endpoint.startsWith("/incidents/") && endpoint.includes("/report")) {
    const id = endpoint.split("/")[2] || "INC-2026-0841";
    const found = DEMO_INCIDENTS.find((i) => i.incident_id === id);
    const rawAlerts = found?.raw_alerts_merged || found?.detection_count || 18;
    const stepsCnt = found?.steps_count || 8;
    const redPct = Math.round((1 - stepsCnt / rawAlerts) * 100);
    return {
      incident_id: id,
      severity: found?.severity || "CRITICAL",
      risk_score: found?.risk_score || 98,
      plain_english_report: found?.plain_english_report || `Incident ${id} has been classified with a prioritized Risk Score of 98/100 (CRITICAL Severity).`,
      report_markdown: `# INCIDENT INVESTIGATION REPORT: ${id}\n\n> **Severity**: ${found?.severity || "CRITICAL"} | **Risk Score**: ${found?.risk_score || 98}/100 | **Status**: ACTIVE_INVESTIGATION\n\n### 1. Executive Summary (Plain English Briefing)\n${found?.plain_english_report || `Adversarial activity was observed across multiple endpoints.`}\n\n### 2. Alert Correlation & Merging Accounting [Bonus B-3]\n- **Raw Alerts Merged**: **${rawAlerts} raw alerts** consolidated into **${stepsCnt} attack steps**.\n- **Alert Fatigue Reduction**: **${redPct}% noise reduction**.\n\n### 3. Chronological Attack Path Narrative\nTraversed multi-stage progression through kill-chain stages.\n\n### 4. Prioritized Action Plan\n- [ ] Isolate compromised endpoints\n- [ ] Revoke user credentials\n- [ ] Rotate sensitive tokens\n\n### 5. Tri-Agent Autonomous Pipeline Provenance\n- **Agent 1 (Detection Analyst)**: Analyzed ${rawAlerts} raw telemetry alerts.\n- **Agent 2 (Forensics Investigator)**: Mapped affected hosts and confirmed root-cause.\n- **Agent 3 (Executive Reporter)**: Synthesized report structure via On-Device Tri-Agent Synthesis Engine.\n`,
      raw_alerts_merged: rawAlerts,
      alert_compression_pct: redPct,
      engine_used: "On-Device Tri-Agent Synthesis Engine",
      generated_at: new Date().toISOString(),
      agent_workflow: {
        analyst_agent: `Triaged ${rawAlerts} alerts with ${redPct}% noise reduction.`,
        forensics_agent: `Mapped ${found?.hosts_involved?.length || 3} hosts.`,
        executive_reporter_agent: "Completed plain English synthesis.",
      },
    } as unknown as T;
  }
  if (endpoint.startsWith("/incidents/") && endpoint.endsWith("/path")) {
    const id = endpoint.split("/")[2];
    const graph = DEMO_INCIDENT_GRAPHS[id] || { steps: DEMO_INCIDENT_DETAIL.steps, edges: DEMO_INCIDENT_DETAIL.edges };
    return { steps: graph.steps, edges: graph.edges } as unknown as T;
  }
  if (endpoint.startsWith("/incidents/") && endpoint.endsWith("/reach")) {
    return DEMO_REACHABILITY_ITEMS as unknown as T;
  }
  if (endpoint.startsWith("/incidents/")) {
    const id = endpoint.split("/")[2];
    const found = DEMO_INCIDENTS.find((i) => i.incident_id === id);
    const graph = DEMO_INCIDENT_GRAPHS[id] || { steps: DEMO_INCIDENT_DETAIL.steps, edges: DEMO_INCIDENT_DETAIL.edges };
    return {
      ...(found || DEMO_INCIDENT_DETAIL),
      steps: graph.steps,
      edges: graph.edges,
    } as unknown as T;
  }
  if (endpoint === "/data-quality") {
    return DEMO_DATA_QUALITY_REPORT as unknown as T;
  }
  if (endpoint === "/bench") {
    return DEMO_BENCHMARK_REPORT as unknown as T;
  }
  if (endpoint.startsWith("/evidence")) {
    const url = new URL(`http://dummy${endpoint}`);
    const eventUid = url.searchParams.get("event_uid");
    if (eventUid && DEMO_RAW_EVIDENCE_MAP[eventUid]) {
      return DEMO_RAW_EVIDENCE_MAP[eventUid] as unknown as T;
    }
    // Return the first available as fallback
    const firstKey = Object.keys(DEMO_RAW_EVIDENCE_MAP)[0];
    return DEMO_RAW_EVIDENCE_MAP[firstKey] as unknown as T;
  }
  if (endpoint === "/rules") {
    return {
      rules_count: 5,
      config_path: "detection_rules.yaml",
      rules: [
        {
          rule_id: "RULE-T1110-001",
          rule_name: "Brute Force Burst",
          technique_id: "T1110.001",
          technique_name: "Password Guessing",
          severity: "HIGH",
          tactic: "Credential Access",
          description: "High volume of failed authentications from a single source IP.",
          query: "SELECT src_ip, count(*) as failure_count FROM events WHERE outcome = 'FAILURE' GROUP BY src_ip HAVING count(*) >= 20",
        },
        {
          rule_id: "RULE-T1046-001",
          rule_name: "Network Port Scan",
          technique_id: "T1046",
          technique_name: "Network Service Discovery",
          severity: "MEDIUM",
          tactic: "Discovery",
          description: "Single source contacting numerous distinct destination ports.",
          query: "SELECT src_ip, dst_ip, count(DISTINCT dst_port) as distinct_ports FROM events GROUP BY src_ip, dst_ip HAVING count(DISTINCT dst_port) >= 10",
        },
        {
          rule_id: "RULE-T1071-001",
          rule_name: "C2 Web Beaconing",
          technique_id: "T1071.001",
          technique_name: "Web Protocols",
          severity: "HIGH",
          tactic: "Command and Control",
          description: "Repetitive outbound connections to external destination IP over HTTP/HTTPS.",
          query: "SELECT src_ip, dst_ip, dst_port, count(*) as beacon_count FROM events WHERE dst_port IN (80, 443, 8080) GROUP BY src_ip, dst_ip, dst_port HAVING count(*) >= 25",
        },
      ],
    } as unknown as T;
  }
  if (endpoint === "/run") {
    return {
      run_id: "RUN-" + Math.floor(Math.random() * 9000 + 1000),
      status: "RUNNING",
      message: "Analysis job started on 30 GB Advanced Tier dataset",
      started_at: new Date().toISOString(),
    } as unknown as T;
  }

  throw new Error(`Synthetic handler not implemented for endpoint: ${endpoint}`);
}

export const pathWardenApi = {
  getStatus: (isDemo = false) => request<ProcessingStatusResponse>("/status", undefined, isDemo),
  startRun: (params: RunAnalysisRequest, isDemo = false) =>
    request<RunAnalysisResponse>(
      "/run",
      {
        method: "POST",
        body: JSON.stringify(params),
      },
      isDemo
    ),
  uploadAndRun: async (file: File, isDemo = false) => {
    const baseUrl = getApiBaseUrl();
    if (!baseUrl) {
      return {
        status: "COMPLETED",
        run_id: "RUN-" + Math.floor(Math.random() * 9000 + 1000),
        filename: file.name,
        events_processed: 10000,
        detections_extracted: 480,
        incidents_count: 25,
        message: `Processed ${file.name} in Synthetic Demo Enclave: 10,000 events, 25 incidents formed.`,
      };
    }

    const res = await fetch(`${baseUrl}/upload-and-run?filename=${encodeURIComponent(file.name)}`, {
      method: "POST",
      headers: {
        "Content-Type": "application/octet-stream",
        "ngrok-skip-browser-warning": "true",
        "Bypass-Tunnel-Reminder": "true",
      },
      body: file,
    });

    if (!res.ok) {
      let detail = "";
      try {
        const errJson = await res.json();
        detail = errJson.detail || errJson.message || "";
      } catch {
        // non-json response
      }
      throw new Error(detail || `File upload failed with HTTP status ${res.status}`);
    }
    return await res.json();
  },
  getIncidents: (isDemo = false) => request<Incident[]>("/incidents", undefined, isDemo),
  getIncident: (id: string, isDemo = false) => request<IncidentDetail>(`/incidents/${id}`, undefined, isDemo),
  getIncidentPath: (id: string, isDemo = false) =>
    request<{ steps: IncidentDetail["steps"]; edges: IncidentDetail["edges"] }>(`/incidents/${id}/path`, undefined, isDemo),
  getIncidentReport: (id: string, forceEngine?: string, isDemo = false) =>
    request<ExecutiveReportResponse>(
      `/incidents/${id}/report${forceEngine ? `?force_engine=${forceEngine}` : ""}`,
      undefined,
      isDemo
    ),
  getReachability: (incidentId?: string, isDemo = false) =>
    request<ReachabilityItem[]>(
      incidentId ? `/incidents/${incidentId}/reach` : "/incidents/INC-001/reach",
      undefined,
      isDemo
    ),
  getDataQuality: (isDemo = false) => request<DataQualityReport>("/data-quality", undefined, isDemo),
  getBenchmark: (isDemo = false) => request<BenchmarkReport>("/bench", undefined, isDemo),
  getEvidence: (eventUid: string, ctx = 5, isDemo = false) =>
    request<RawEvidenceRecord>(`/evidence?event_uid=${encodeURIComponent(eventUid)}&ctx=${ctx}`, undefined, isDemo),
  // Bonus B-4: Rules Configuration
  getRules: (isDemo = false) => request<RulesResponse>("/rules", undefined, isDemo),
  createRule: (rule: DetectionRule, isDemo = false) =>
    request<{ status: string; message: string; rule: DetectionRule }>(
      "/rules",
      {
        method: "POST",
        body: JSON.stringify(rule),
      },
      isDemo
    ),
  updateRule: (ruleId: string, rule: DetectionRule, isDemo = false) =>
    request<{ status: string; message: string; rule: DetectionRule }>(
      `/rules/${ruleId}`,
      {
        method: "PUT",
        body: JSON.stringify(rule),
      },
      isDemo
    ),
  deleteRule: (ruleId: string, isDemo = false) =>
    request<{ status: string; message: string }>(`/rules/${ruleId}`, { method: "DELETE" }, isDemo),
  hasBackendUrl: () => Boolean(getApiBaseUrl()),
};

