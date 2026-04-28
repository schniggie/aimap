import type {
  AgentEndpoint,
  AgentAnalysis,
  Scan,
  ScanConfig,
  MonitoredRange,
  PaginatedResponse,
  ApiStatsResponse,
  GeoAggregation,
} from "@/types";

import { getAuthToken } from "./auth";

const BASE_URL = "/api";

async function request<T>(url: string, options?: RequestInit): Promise<T> {
  const token = await getAuthToken();
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    ...(options?.headers as Record<string, string>),
  };
  if (token) {
    headers["Authorization"] = `Bearer ${token}`;
  }

  const res = await fetch(`${BASE_URL}${url}`, {
    ...options,
    headers,
  });

  if (!res.ok) {
    throw new Error(`API Error: ${res.status} ${res.statusText}`);
  }

  // Handle 204 No Content
  if (res.status === 204) {
    return undefined as unknown as T;
  }

  return res.json() as Promise<T>;
}

// -- Endpoints ----------------------------------------------------------------

export function getEndpoints(params?: {
  page?: number;
  page_size?: number;
  protocol?: string;
  auth_status?: string;
  risk_min?: number;
  risk_max?: number;
  country?: string;
  tool?: string;
  tag?: string;
  q?: string;
  sort_by?: string;
}) {
  const searchParams = new URLSearchParams();
  if (params) {
    Object.entries(params).forEach(([key, value]) => {
      if (value !== undefined && value !== "") {
        searchParams.set(key, String(value));
      }
    });
  }
  const qs = searchParams.toString();
  return request<PaginatedResponse<AgentEndpoint>>(
    `/endpoints${qs ? `?${qs}` : ""}`
  );
}

export function getEndpointById(id: string) {
  return request<AgentEndpoint>(`/endpoints/${id}`);
}

export function searchEndpoints(query: string, page = 1, pageSize = 25) {
  const qs = new URLSearchParams({
    page: String(page),
    page_size: String(pageSize),
  }).toString();
  return request<PaginatedResponse<AgentEndpoint>>(
    `/endpoints/search?${qs}`,
    {
      method: "POST",
      body: JSON.stringify({ query }),
    }
  );
}

// -- Stats --------------------------------------------------------------------

export function getStats() {
  return request<ApiStatsResponse>("/endpoints/stats");
}

export function getGeoData() {
  return request<GeoAggregation[]>("/endpoints/geo");
}

export function getGlobeData() {
  return request<import("@/components/GlobeVisualization").GlobePoint[]>(
    "/endpoints/globe",
  );
}

// -- Analysis -----------------------------------------------------------------

export function getAnalysis(endpointId: string) {
  return request<AgentAnalysis>(`/analyses/${endpointId}`);
}

// -- Scans --------------------------------------------------------------------

export function getScans(params?: {
  status?: string;
  scan_type?: string;
  created_by?: string;
  page?: number;
  page_size?: number;
}) {
  const searchParams = new URLSearchParams();
  if (params) {
    Object.entries(params).forEach(([key, value]) => {
      if (value !== undefined && value !== "") {
        searchParams.set(key, String(value));
      }
    });
  }
  const qs = searchParams.toString();
  return request<PaginatedResponse<Scan>>(`/scans${qs ? `?${qs}` : ""}`);
}

export function createScan(config: {
  name: string;
  type: "active" | "ingestion";
  config: Partial<ScanConfig>;
}) {
  return request<Scan>("/scans", {
    method: "POST",
    body: JSON.stringify(config),
  });
}

export function updateScanStatus(id: string, status: string) {
  return request<Scan>(`/scans/${id}/status`, {
    method: "PUT",
    body: JSON.stringify({ status }),
  });
}

export function runScan(id: string) {
  return request<{ id: string; status: string; message: string }>(
    `/scans/${id}/run`,
    { method: "POST" }
  );
}

export function getQueryPresets() {
  return request<{
    presets: { key: string; query: string; description: string }[];
  }>("/scans/query-presets");
}

// -- Ranges -------------------------------------------------------------------

export function getRanges(params?: { page?: number; page_size?: number }) {
  const searchParams = new URLSearchParams();
  if (params) {
    Object.entries(params).forEach(([key, value]) => {
      if (value !== undefined) {
        searchParams.set(key, String(value));
      }
    });
  }
  const qs = searchParams.toString();
  return request<PaginatedResponse<MonitoredRange>>(
    `/ranges${qs ? `?${qs}` : ""}`
  );
}

export function createRange(data: {
  name: string;
  cidr: string;
  monitoring: { enabled: boolean; interval_hours: number };
}) {
  return request<MonitoredRange>("/ranges", {
    method: "POST",
    body: JSON.stringify(data),
  });
}

export function deleteRange(id: string) {
  return request<void>(`/ranges/${id}`, { method: "DELETE" });
}

export function triggerRangeScan(id: string) {
  return request<{ scan_id: string; range_id: string; status: string }>(
    `/ranges/${id}/scan`,
    { method: "POST" }
  );
}

export function triggerRangeIngestion(id: string) {
  return request<{ scan_id: string; range_id: string; status: string }>(
    `/ranges/${id}/scan`,
    {
      method: "POST",
      body: JSON.stringify({ type: "ingestion" }),
    }
  );
}

// -- Attack / Testing ---------------------------------------------------------

export interface AttackStartResponse {
  attack_id: string;
  endpoint_id: string;
  status: string;
  target_url: string;
}

export function startAttack(
  endpointId: string,
  config: {
    techniques: string[];
    depth: string;
    max_steps: number;
  }
) {
  return request<AttackStartResponse>(`/attack/${endpointId}`, {
    method: "POST",
    body: JSON.stringify(config),
  });
}

/**
 * Open a WebSocket to stream live attack log entries.
 * Returns a cleanup function to close the socket.
 */
export function streamAttackLogs(
  attackId: string,
  onEntry: (entry: import("@/types").AttackLogEntry) => void,
  onDone: () => void,
  onError?: (err: Event) => void,
): () => void {
  const proto = window.location.protocol === "https:" ? "wss:" : "ws:";
  const wsUrl = `${proto}//${window.location.host}/api/attack/${attackId}/stream`;
  const ws = new WebSocket(wsUrl);

  ws.onmessage = (event) => {
    try {
      const data = JSON.parse(event.data);
      if (data.type === "DONE") {
        onDone();
        ws.close();
        return;
      }
      if (data.error) {
        onDone();
        ws.close();
        return;
      }
      onEntry(data);
    } catch {
      // ignore parse errors
    }
  };

  ws.onerror = (event) => {
    onError?.(event);
  };

  ws.onclose = () => {
    onDone();
  };

  return () => {
    ws.close();
  };
}
