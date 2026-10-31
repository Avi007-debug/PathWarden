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
} from "./types";
import {
  DEMO_INCIDENTS,
  DEMO_INCIDENT_DETAIL,
  DEMO_REACHABILITY_ITEMS,
  DEMO_DATA_QUALITY_REPORT,
  DEMO_BENCHMARK_REPORT,
  DEMO_PROCESSING_STATUS,
  DEMO_RAW_EVIDENCE_MAP,
} from "../demo/syntheticData";

export const getApiBaseUrl = (): string => {
  if (process.env.NEXT_PUBLIC_API_BASE_URL) return process.env.NEXT_PUBLIC_API_BASE_URL;
  if (process.env.NEXT_PUBLIC_API_URL) return process.env.NEXT_PUBLIC_API_URL;
  if (typeof window !== "undefined") {
    const isLocalhost =
      window.location.hostname === "localhost" ||
      window.location.hostname === "127.0.0.1";
    if (isLocalhost) return "http://localhost:8000";
  }
  return "";
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
  if (endpoint.startsWith("/incidents/") && endpoint.endsWith("/path")) {
    const id = endpoint.split("/")[2];
    if (id === DEMO_INCIDENT_DETAIL.incident_id) {
      return { steps: DEMO_INCIDENT_DETAIL.steps, edges: DEMO_INCIDENT_DETAIL.edges } as unknown as T;
    }
    return { steps: DEMO_INCIDENT_DETAIL.steps, edges: DEMO_INCIDENT_DETAIL.edges } as unknown as T;
  }
  if (endpoint.startsWith("/incidents/") && endpoint.endsWith("/reach")) {
    return DEMO_REACHABILITY_ITEMS as unknown as T;
  }
  if (endpoint.startsWith("/incidents/")) {
    const id = endpoint.split("/")[2];
    const found = DEMO_INCIDENTS.find((i) => i.incident_id === id);
    if (found && id === DEMO_INCIDENT_DETAIL.incident_id) {
      return DEMO_INCIDENT_DETAIL as unknown as T;
    }
    return { ...(found || DEMO_INCIDENT_DETAIL), steps: DEMO_INCIDENT_DETAIL.steps, edges: DEMO_INCIDENT_DETAIL.edges } as unknown as T;
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
  getIncidents: (isDemo = false) => request<Incident[]>("/incidents", undefined, isDemo),
  getIncident: (id: string, isDemo = false) => request<IncidentDetail>(`/incidents/${id}`, undefined, isDemo),
  getIncidentPath: (id: string, isDemo = false) =>
    request<{ steps: IncidentDetail["steps"]; edges: IncidentDetail["edges"] }>(`/incidents/${id}/path`, undefined, isDemo),
  getReachability: (incidentId?: string, isDemo = false) =>
    request<ReachabilityItem[]>(
      incidentId ? `/incidents/${incidentId}/reach` : "/incidents/INC-2026-0841/reach",
      undefined,
      isDemo
    ),
  getDataQuality: (isDemo = false) => request<DataQualityReport>("/data-quality", undefined, isDemo),
  getBenchmark: (isDemo = false) => request<BenchmarkReport>("/bench", undefined, isDemo),
  getEvidence: (eventUid: string, ctx = 5, isDemo = false) =>
    request<RawEvidenceRecord>(`/evidence?event_uid=${encodeURIComponent(eventUid)}&ctx=${ctx}`, undefined, isDemo),
  hasBackendUrl: () => Boolean(getApiBaseUrl()),
};

