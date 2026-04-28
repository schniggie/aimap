// ── Agent Endpoint (core discovery record) ──────────────────────────────────

export type RiskLevel = "critical" | "high" | "medium" | "low" | "info";
export type Protocol =
  | "mcp"
  | "langserve"
  | "openai_compat"
  | "autogen"
  | "ollama"
  | "gradio"
  | "streamlit"
  | "comfyui"
  | "stable_diffusion"
  | "textgen_webui"
  | "openclaw"
  | "open_webui"
  | "librechat"
  | "huggingface"
  | "unknown";
export type AuthStatus = "none" | "api_key" | "oauth" | "basic" | "unknown";
export type ScanStatus = "queued" | "running" | "paused" | "completed" | "failed" | "cancelled";
export type TestStatus = "pending" | "running" | "completed" | "failed";

export interface ToolInfo {
  name: string;
  description: string;
  parameters: Record<string, unknown>;
  risk: RiskLevel;
  risk_reason: string;
}

export interface GeoInfo {
  country: string;
  country_code: string;
  region: string;
  city: string;
  lat: number;
  lon: number;
  asn: string;
  org: string;
}

export interface ServerInfo {
  banner: string;
  headers: Record<string, string>;
  tls: boolean;
  cors_open: boolean;
}

export interface SourceRecord {
  source: string;
  scan_id?: string;
  template?: string;
  discovered_at: string;
  raw_data: Record<string, unknown>;
}

export interface AgentEndpoint {
  id: string;
  _id?: string;
  ip: string;
  port: number;
  hostname: string;
  url: string;
  protocol: Protocol;
  framework: string;
  model: string;
  auth_status: AuthStatus;
  tools: ToolInfo[];
  tool_count: number;
  dangerous_combos: string[];
  system_prompt: string;
  system_prompt_extracted: boolean;
  risk_score: number;
  risk_factors: string[];
  geo: GeoInfo;
  server: ServerInfo;
  sources: SourceRecord[];
  range_id?: string;
  scan_ids: string[];
  analysis_id?: string;
  first_seen: string;
  last_seen: string;
  created_at: string;
  updated_at: string;
  tags: string[];
}

// ── Agent Analysis (deep-dive record) ───────────────────────────────────────

export interface ToolDetail {
  name: string;
  description: string;
  input_schema: Record<string, unknown>;
  risk: RiskLevel;
  risk_reason: string;
  injectable: boolean;
  tested: boolean;
  injection_vector?: string;
}

export interface Fingerprint {
  protocol_version: string;
  capabilities: string[];
  tool_details: ToolDetail[];
  system_prompt_full: string;
  model_detected: string;
  model_detection_method: string;
  permission_model: string;
  rate_limiting: boolean;
  input_validation: string;
}

export interface ScanFinding {
  template: string;
  severity: RiskLevel;
  title: string;
  detail: string;
  evidence: Record<string, unknown>;
}

export interface ActiveScan {
  scan_id: string;
  scan_type: string;
  started_at: string;
  completed_at: string;
  status: ScanStatus;
  templates_run: string[];
  findings: ScanFinding[];
  raw_output: string;
}

export interface AttackNode {
  id: string;
  type: "entry_point" | "technique" | "tool" | "impact";
  label: string;
  success?: boolean;
}

export interface AttackEdge {
  from: string;
  to: string;
}

export interface AttackGraph {
  nodes: AttackNode[];
  edges: AttackEdge[];
}

export interface TestResult {
  test_id: string;
  category: string;
  technique: string;
  payload: string;
  response: string;
  success: boolean;
  severity: RiskLevel;
  chain?: string[];
  timestamp: string;
}

export interface ExploitationLogEntry {
  step: number;
  reasoning: string;
  action: string;
  result: string;
  timestamp: string;
}

export interface TestingInfo {
  status: TestStatus;
  last_tested_at: string;
  attack_surface: string[];
  attack_graph: AttackGraph;
  test_results: TestResult[];
  exploitation_log: ExploitationLogEntry[];
}

export interface AgentAnalysis {
  id: string;
  _id?: string;
  endpoint_id: string;
  fingerprint: Fingerprint;
  active_scans: ActiveScan[];
  testing: TestingInfo;
  created_at: string;
  updated_at: string;
  analyzed_by: string;
  tags: string[];
}

// ── Scans ───────────────────────────────────────────────────────────────────

export interface ScanConfig {
  type?: "active" | "ingestion";
  target: string;
  range_id?: string;
  protocols: Protocol[];
  templates: string[];
  ports: number[];
  rate_limit: number;
  timeout_ms: number;
  source?: string;
  query?: string;
  queries?: string[];
  max_results?: number;
  max_results_per_query?: number;
}

export interface ScanProgress {
  total_hosts: number;
  scanned: number;
  alive: number;
  agents_found: number;
  percent_complete: number;
  current_ip: string;
  started_at: string;
  estimated_completion: string;
}

export interface ResultsSummary {
  total_endpoints: number;
  by_protocol: Record<string, number>;
  by_risk: Record<RiskLevel, number>;
  no_auth_count: number;
}

export interface Scan {
  id: string;
  _id?: string;
  name: string;
  type: "active" | "ingestion";
  status: ScanStatus;
  config: ScanConfig;
  progress: ScanProgress;
  results_summary: ResultsSummary;
  endpoint_ids: string[];
  created_by: string;
  created_at: string;
  updated_at: string;
}

// ── Ranges ──────────────────────────────────────────────────────────────────

export interface MonitoringConfig {
  enabled: boolean;
  interval_hours: number;
  last_scan_id: string;
  last_scanned_at: string;
  next_scan_at: string;
}

export interface RangeTrend {
  endpoints_7d_ago: number;
  endpoints_30d_ago: number;
  direction: "increasing" | "decreasing" | "stable";
}

export interface RangeStats {
  total_endpoints: number;
  by_protocol: Record<string, number>;
  by_risk: Record<RiskLevel, number>;
  no_auth_count: number;
  trend: RangeTrend;
}

export interface MonitoredRange {
  id: string;
  _id?: string;
  name: string;
  cidr: string;
  total_hosts: number;
  monitoring: MonitoringConfig;
  stats: RangeStats;
  scan_ids: string[];
  created_by: string;
  created_at: string;
  updated_at: string;
  tags: string[];
}

// ── API Response Types ──────────────────────────────────────────────────────

export interface PaginatedResponse<T> {
  items: T[];
  total: number;
  page: number;
  page_size: number;
}

export interface GeoAggregation {
  country_code: string;
  country: string;
  count: number;
  lat: number;
  lon: number;
}

/** Backend API stats response from GET /api/endpoints/stats */
export interface ApiStatsResponse {
  total: number;
  by_protocol: Record<string, number>;
  by_risk: Record<string, number>;
  by_auth: Record<string, number>;
  no_auth_count: number;
}

/** Frontend mock stats shape (used for fallback display) */
export interface StatsResponse {
  total_endpoints: number;
  critical_count: number;
  no_auth_percent: number;
  by_protocol: Record<string, number>;
  by_risk: Record<RiskLevel, number>;
  recent_discoveries: AgentEndpoint[];
}

// ── Live Attack Log Entry (for TestAgent page) ──────────────────────────────

export type AttackLogType = "REASONING" | "PAYLOAD" | "RESPONSE" | "FINDING";

export interface AttackLogEntry {
  timestamp: string;
  type: AttackLogType;
  content: string;
  severity?: RiskLevel;
}
