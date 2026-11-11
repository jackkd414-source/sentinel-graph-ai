// Typed API surface. Mirrors the FastAPI routes exactly - if a field is not
// returned by the backend, it is not declared here.

export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type EdgeStatus = "observed" | "inferred";
export type TsStatus = "ok" | "assumed" | "invalid" | "missing";

export interface HealthCounts {
  projects: number;
  artifacts: number;
  events: number;
  alerts: number;
  incidents: number;
  graph_nodes: number;
  graph_edges: number;
  iocs: number;
  reports: number;
}

export interface AiStatus {
  mode: "core_only" | "ai_enabled" | "missing_credential";
  label: string;
  detail: string;
  provider: string | null;
  model: string | null;
  credential_hint?: string;
  last_test_status: string | null;
  last_test_at: string | null;
  encryption_available: boolean;
}

export interface Health {
  status: string;
  version: string;
  db: string;
  counts: HealthCounts;
  ai: AiStatus;
  time: string;
}

export interface Project {
  id: number;
  name: string;
  description: string | null;
  is_demo: number;
  created_at: string;
  updated_at: string;
}

export interface Artifact {
  id: number;
  project_id: number;
  name: string;
  source_type: string;
  artifact_kind: string;
  stored_path: string | null;
  sha256: string | null;
  size_bytes: number | null;
  record_total: number;
  record_ok: number;
  record_failed: number;
  parse_status: "pending" | "ok" | "partial" | "failed";
  parse_notes: string | null;
  is_synthetic: number;
  imported_at: string;
}

export interface EventRow {
  id: number;
  project_id: number;
  artifact_id: number | null;
  external_id: string | null;
  ts_raw: string | null;
  ts_utc: string | null;
  ts_status: TsStatus;
  source: string;
  event_type: string;
  action: string | null;
  severity: Severity | null;
  host: string | null;
  user_name: string | null;
  src_ip: string | null;
  dst_ip: string | null;
  dst_port: number | null;
  domain: string | null;
  url: string | null;
  file_path: string | null;
  file_hash: string | null;
  process_name: string | null;
  process_id: string | null;
  parent_process: string | null;
  parent_pid: string | null;
  command_line: string | null;
  bytes_out: number | null;
  raw: string | null;
  created_at: string;
  role?: string;
}

export interface EventFacets {
  hosts: string[];
  users: string[];
  event_types: string[];
  severities: string[];
  sources: string[];
  timestamp_issues: { ts_status: string; c: number }[];
}

export interface Alert {
  id: number;
  project_id: number;
  rule_id: string;
  title: string;
  severity: Severity;
  narrative: string;
  host: string | null;
  user_name: string | null;
  first_ts: string | null;
  last_ts: string | null;
  incident_id: number | null;
  dedup_key?: string;
  created_at?: string;
  rule_name?: string;
  rule_logic?: string;
  /**
   * Resolved evidence rows. The API returns the actual event objects, not bare
   * IDs, so callers can render evidence without a second round-trip.
   */
  evidence: EventRow[];
}

export interface IncidentSummary {
  id: number;
  project_id: number;
  ref: string;
  title: string;
  severity: Severity;
  status: "open" | "investigating" | "contained" | "closed";
  summary: string | null;
  first_ts: string | null;
  last_ts: string | null;
  created_at: string;
  updated_at: string;
  alerts: { id: number; rule_id: string; title: string; severity: Severity }[];
  alert_count: number;
  hosts: string[];
}

export interface TimelineEntry {
  id: number;
  ts_utc: string | null;
  ts_status: TsStatus;
  ts_raw: string | null;
  host: string | null;
  user: string | null;
  event_type: string;
  source: string;
  detail: string | null;
  severity: Severity | null;
}

export interface StatusHistoryEntry {
  id: number;
  incident_id: number;
  from_status: string | null;
  to_status: string;
  note: string | null;
  changed_at: string;
}

export interface AiRun {
  id: number;
  incident_id: number | null;
  task: string;
  provider: string | null;
  model: string | null;
  status: string;
  latency_ms: number | null;
  prompt_tokens: number | null;
  output_tokens: number | null;
  result_json: AiResult | { raw_output: string } | null;
  error_category: string | null;
  error_message: string | null;
  created_at: string;
}

export interface AiHypothesis {
  statement: string;
  confidence: "low" | "medium" | "high";
  supporting_event_ids: number[];
  contradicting_event_ids: number[];
  reasoning: string;
  /** Set by the evidence guard after citations are checked against the DB. */
  evidence_status?: "supported" | "contested" | "unsupported";
}

export interface AiResult {
  summary: string;
  timeline_interpretation: string;
  hypotheses: AiHypothesis[];
  root_cause_hypothesis: { statement: string; confidence: string };
  missing_information: string[];
  next_investigation_steps: string[];
  uncertainty_notes: string;
  summary_is_unverified?: boolean;
  unsupported_hypotheses?: string[];
  stripped_reference_count?: number;
}

export interface IncidentDetail {
  incident: IncidentSummary;
  alerts: Alert[];
  events: EventRow[];
  timeline: TimelineEntry[];
  status_history: StatusHistoryEntry[];
  ai_status: AiStatus;
  ai_runs: AiRun[];
}

export interface GraphNode {
  id: number;
  project_id: number;
  node_key: string;
  node_type: string;
  label: string;
  severity: Severity | null;
  attributes: Record<string, unknown>;
}

export interface GraphEdge {
  id: number;
  project_id: number;
  src_node_id: number;
  dst_node_id: number;
  relation: string;
  status: EdgeStatus;
  method: string;
  confidence: string;
  first_ts: string | null;
  last_ts: string | null;
  /** Events proving this relation. Empty for purely derived structural edges. */
  evidence_event_ids?: number[];
}

export interface GraphData {
  nodes: GraphNode[];
  edges: GraphEdge[];
  stats: { node_count: number; edge_count: number };
}

export interface NodeDetail {
  node: GraphNode;
  incoming: (GraphEdge & { src_key: string; src_label: string; src_type: string })[];
  outgoing: (GraphEdge & { dst_key: string; dst_label: string; dst_type: string })[];
  evidence: EventRow[];
}

export interface Rule {
  id: string;
  name: string;
  category: string;
  description: string;
  logic: string;
  severity: Severity;
  version: string;
  enabled: number;
}

export interface ProviderConfig {
  id: number;
  name: string;
  provider_type: string;
  base_url: string | null;
  model_id: string;
  fast_model_id: string | null;
  secret_source: "db" | "env" | "none";
  timeout_s: number;
  max_output_tokens: number | null;
  is_active: number;
  allow_fallback: number;
  last_test_status: string | null;
  last_test_at: string | null;
  last_test_latency_ms: number | null;
  last_test_error: string | null;
  created_at: string;
  updated_at: string;
  credential_hint: string;
  credential_configured: boolean;
  encryption_available: boolean;
}

export interface ProviderTypeMeta {
  label: string;
  base_url: string;
  needs_key: boolean;
  supports_model_list: boolean;
}

export interface TestResult {
  ok: boolean;
  provider: string;
  model: string;
  base_url?: string;
  latency_ms: number;
  error_category: string | null;
  error_message: string;
  sample_reply?: string;
  checked_at: string;
}

export interface IngestResult {
  records_total: number;
  records_ok: number;
  records_failed: number;
  events_inserted: number;
  events_duplicated: number;
  parse_status: string;
  format?: string;
  artifact_id?: number;
  failures?: { record: number; reason: string }[];
  warnings?: string[];
  /** Present when the import actually ran detection (not preview). */
  analysis?: {
    events_analyzed: number;
    alerts_created: number;
    alerts_by_severity: Record<string, number>;
    incidents_created: number;
    graph: { nodes: number; edges: number };
    engine_errors: { rule_id: string; error: string }[];
  };
}

export interface DemoLoadResult {
  project_id: number;
  import: {
    records_total: number;
    records_ok: number;
    records_failed: number;
    events_inserted: number;
    events_duplicated: number;
    parse_status: string;
  };
  edge_case_import: {
    records_total: number;
    records_ok: number;
    records_failed: number;
    parse_status: string;
    failures: { record: number; reason: string }[];
  };
  analysis: {
    events_analyzed: number;
    alerts_created: number;
    alerts_by_severity: Record<string, number>;
    incidents_created: number;
    graph: { nodes: number; edges: number };
    engine_errors: { rule_id: string; error: string }[];
    ioc_count: number;
  };
  ground_truth: Record<string, unknown>;
  notice: string;
}

export class ApiError extends Error {
  status: number;
  detail: string;
  constructor(status: number, detail: string) {
    super(detail);
    this.status = status;
    this.detail = detail;
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(path, {
    headers: { "Content-Type": "application/json", ...(init?.headers || {}) },
    ...init,
  });
  if (!res.ok) {
    let detail = `HTTP ${res.status}`;
    try {
      const body = await res.json();
      if (typeof body.detail === "string") detail = body.detail;
      else if (Array.isArray(body.detail)) detail = body.detail.map((d: { msg: string }) => d.msg).join("; ");
    } catch {
      /* non-JSON error body */
    }
    throw new ApiError(res.status, detail);
  }
  if (res.status === 204) return undefined as T;
  return (await res.json()) as T;
}

const qs = (params: Record<string, string | number | boolean | undefined | null>) => {
  const sp = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) {
    if (v !== undefined && v !== null && v !== "") sp.set(k, String(v));
  }
  const s = sp.toString();
  return s ? `?${s}` : "";
};

export const api = {
  health: () => request<Health>("/api/health"),
  projects: () => request<{ projects: Project[] }>("/api/projects"),

  artifacts: (projectId?: number) =>
    request<{ artifacts: Artifact[] }>(`/api/artifacts${qs({ project_id: projectId })}`),
  deleteArtifact: (id: number) =>
    request<{ deleted_artifact: string; events_removed: number }>(
      `/api/artifacts/${id}`, { method: "DELETE" }),
  resetData: (keepIocs = true) =>
    request<{ cleared: Record<string, number>; keep_iocs: boolean; counts: Record<string, number> }>(
      `/api/data/reset?keep_iocs=${keepIocs}`, { method: "POST" }),

  events: (params: {
    project_id?: number; limit?: number; offset?: number; host?: string;
    user?: string; event_type?: string; severity?: string; q?: string;
    order?: "asc" | "desc";
  }) => request<{ events: EventRow[]; total: number; limit: number; offset: number }>(
    `/api/events${qs(params)}`),
  eventFacets: (projectId?: number) =>
    request<EventFacets>(`/api/events/facets${qs({ project_id: projectId })}`),

  alerts: (projectId?: number) =>
    request<{ alerts: Alert[] }>(`/api/alerts${qs({ project_id: projectId })}`),
  incidents: (projectId?: number) =>
    request<{ incidents: IncidentSummary[] }>(`/api/incidents${qs({ project_id: projectId })}`),
  incident: (id: number) => request<IncidentDetail>(`/api/incidents/${id}`),
  setStatus: (id: number, status: string, note?: string) =>
    request<{ id: number; status: string; previous: string }>(
      `/api/incidents/${id}/status`,
      { method: "PATCH", body: JSON.stringify({ status, note }) }),

  graph: (params: {
    project_id?: number; include_inferred?: boolean; node_types?: string;
    min_severity?: string; search?: string;
  }) => request<GraphData>(`/api/graph${qs(params)}`),
  nodeDetail: (id: number) => request<NodeDetail>(`/api/graph/nodes/${id}`),

  rules: () => request<{ rules: Rule[] }>("/api/rules"),
  toggleRule: (id: string, enabled: boolean) =>
    request<{ id: string; enabled: boolean }>(`/api/rules/${id}`,
      { method: "PATCH", body: JSON.stringify({ enabled }) }),
  reanalyze: (projectId?: number) =>
    request<DemoLoadResult["analysis"]>(`/api/analyze${qs({ project_id: projectId })}`,
      { method: "POST" }),

  demoLoad: (projectId?: number, reset = true) =>
    request<DemoLoadResult>(`/api/demo/load${qs({ project_id: projectId, reset })}`,
      { method: "POST" }),

  ingestText: (body: {
    text: string; filename: string; source_type?: string;
    project_id?: number; preview_only?: boolean;
  }) => request<IngestResult>("/api/ingest/text",
    { method: "POST", body: JSON.stringify(body) }),

  aiStatus: () => request<{
    status: AiStatus;
    providers: Record<string, ProviderTypeMeta>;
  }>("/api/ai/status"),
  providers: () => request<{
    configs: ProviderConfig[];
    types: Record<string, ProviderTypeMeta>;
    encryption_available: boolean;
  }>("/api/ai/providers"),
  createProvider: (body: Record<string, unknown>) =>
    request<ProviderConfig>("/api/ai/providers",
      { method: "POST", body: JSON.stringify(body) }),
  updateProvider: (id: number, body: Record<string, unknown>) =>
    request<ProviderConfig>(`/api/ai/providers/${id}`,
      { method: "PATCH", body: JSON.stringify(body) }),
  activateProvider: (id: number, active: boolean) =>
    request<ProviderConfig>(`/api/ai/providers/${id}/activate`,
      { method: "POST", body: JSON.stringify({ active }) }),
  deleteProvider: (id: number) =>
    request<{ deleted: boolean }>(`/api/ai/providers/${id}`, { method: "DELETE" }),
  testProvider: (id: number) =>
    request<TestResult>(`/api/ai/providers/${id}/test`, { method: "POST" }),
  providerModels: (id: number) =>
    request<{ ok: boolean; models: string[]; error?: string }>(
      `/api/ai/providers/${id}/models`, { method: "POST" }),

  analyzeIncident: (id: number, task = "summarize") =>
    request<{
      status: string;
      run_id?: number;
      message?: string;
      provider?: string;
      model?: string;
      latency_ms?: number;
      analysis?: AiResult;
      issues?: string[];
      error_category?: string;
      error_message?: string;
      manifest?: Record<string, unknown>;
    }>(`/api/incidents/${id}/analyze${qs({ task })}`, { method: "POST" }),

  report: (id: number, fmt: "md" | "json" | "html") =>
    request<{ id: number | null; fmt: string; content: string; incident_ref: string }>(
      `/api/incidents/${id}/report${qs({ fmt })}`, { method: "POST" }),
  reportUrl: (id: number, fmt: "md" | "json" | "html") =>
    `/api/incidents/${id}/report${qs({ fmt })}`,

  audit: () => request<{
    entries: { id: number; action: string; target: string | null;
               detail: string | null; created_at: string }[];
  }>("/api/audit"),
};
