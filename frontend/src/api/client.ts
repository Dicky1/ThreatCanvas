import type {
  CollectiveDefenseResult,
  CoverageReport,
  AttackTimeline,
  BenchmarkReport,
  ConsensusResult,
  CTIFetchResult,
  DetectionValidationResult,
  AlertIngestResponse,
  CIRSpecification,
  ConversionResponse,
  CtiIngestResponse,
  DetectionDataset,
  DetectionTarget,
  EvaluationReport,
  GraphAnalysis,
  ParseResponse,
  PurplePlan,
  PurpleRun,
  ResearchMetricResult,
  Scenario,
  SimulationResult,
} from '../types/api';

const API_BASE_URL = (import.meta.env.VITE_API_BASE_URL || '/api').replace(/\/$/, '');

// Shared with useAuthStore so both sides agree on where the JWT lives.
export const TOKEN_KEY = 'tc_token';
export const USER_KEY = 'tc_user';

export class ApiError extends Error {
  public readonly status: number;
  /** Raw `detail` from the backend (may be a structured object). */
  public readonly detail: unknown;

  constructor(status: number, message: string, detail?: unknown) {
    super(message);
    this.status = status;
    this.detail = detail;
    this.name = 'ApiError';
  }
}

function formatErrorDetail(detail: unknown): string {
  if (typeof detail === 'string') return detail;
  if (detail instanceof Error) return detail.message;
  if (detail !== null && detail !== undefined) {
    try {
      return JSON.stringify(detail);
    } catch {
      return 'The backend returned an unreadable error.';
    }
  }
  return 'The request failed.';
}

function authHeader(): Record<string, string> {
  try {
    const token = localStorage.getItem(TOKEN_KEY);
    return token ? { Authorization: `Bearer ${token}` } : {};
  } catch {
    return {};
  }
}

const DEFAULT_TIMEOUT_MS = 20_000;
// LLM-backed calls may run several self-repair rounds.
export const LLM_TIMEOUT_MS = 180_000;
// Dataset uploads / evaluations can take a while on large files.
export const UPLOAD_TIMEOUT_MS = 120_000;

async function request<T>(path: string, init?: RequestInit, timeoutMs = DEFAULT_TIMEOUT_MS): Promise<T> {
  const controller = new AbortController();
  const timeout = window.setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetch(`${API_BASE_URL}${path}`, {
      ...init,
      signal: controller.signal,
      headers: { Accept: 'application/json', ...authHeader(), ...init?.headers },
    });
    const text = await response.text();
    let body: unknown = null;
    try {
      body = text ? JSON.parse(text) : null;
    } catch {
      body = text;
    }
    if (!response.ok) {
      const rawDetail = typeof body === 'object' && body !== null && 'detail' in body
        ? (body as { detail: unknown }).detail
        : undefined;
      const detail = rawDetail !== undefined
        ? formatErrorDetail(rawDetail)
        : `Request failed with HTTP ${response.status}`;
      if (response.status === 401) {
        // Token missing/expired/invalid: clear it and let the app react
        // (useAuthStore listens for this and redirects to /login).
        try {
          localStorage.removeItem(TOKEN_KEY);
          localStorage.removeItem(USER_KEY);
        } catch {
          /* localStorage unavailable - nothing to clean up */
        }
        window.dispatchEvent(new CustomEvent('tc:unauthorized'));
      }
      throw new ApiError(response.status, detail, rawDetail);
    }
    return body as T;
  } catch (error) {
    if (error instanceof DOMException && error.name === 'AbortError') {
      throw new Error('Request timed out. Check that the backend is available.');
    }
    throw error;
  } finally {
    window.clearTimeout(timeout);
  }
}

/** Authenticated request returning a file (Blob) plus its suggested filename. */
async function requestFile(path: string, init?: RequestInit): Promise<{ blob: Blob; filename: string }> {
  const response = await fetch(`${API_BASE_URL}${path}`, { ...init, headers: { ...authHeader(), ...init?.headers } });
  if (!response.ok) {
    let detail = `Request failed with HTTP ${response.status}`;
    try {
      const body = await response.json();
      if (body && 'detail' in body) detail = formatErrorDetail(body.detail);
    } catch { /* non-JSON error body */ }
    if (response.status === 401) window.dispatchEvent(new CustomEvent('tc:unauthorized'));
    throw new ApiError(response.status, detail);
  }
  const disposition = response.headers.get('content-disposition') || '';
  const filename = /filename="([^"]+)"/.exec(disposition)?.[1] || 'download';
  return { blob: await response.blob(), filename };
}

export const api = {
  health: () => fetch('/health').then((response) => {
    if (!response.ok) throw new ApiError(response.status, 'Backend health check failed');
    return response.json() as Promise<{ status: string }>;
  }),
  parse: (scenario: string) => request<ParseResponse>('/v1/parse', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ scenario }),
  }, LLM_TIMEOUT_MS),
  login: (username: string, password: string) => {
    const body = new URLSearchParams({ username, password });
    return request<{ access_token: string; user: unknown }>('/v1/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body,
    });
  },
  register: (payload: unknown) => request<unknown>('/v1/auth/register', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  }),
  scenarios: () => request<Scenario[]>('/v1/scenarios'),
  scenario: (id: string) => request<Scenario & { cir_graph_data: CIRSpecification }>(`/v1/scenarios/${encodeURIComponent(id)}`),
  coverage: (id: string) => request<CoverageReport>(`/v1/coverage/${id}`),
  analysis: (id: string) => request<GraphAnalysis>(`/v1/graph-analysis/${id}`),
  reasoning: (id: string) => request<Record<string, unknown>>(`/v1/reasoning/${id}`),
  artifact: (id: string, type: 'sigma' | 'kql' | 'spl') => request<{ artifact_type: string; content: string; state: string }>(`/v1/compile/${type}/${id}`),
  validateArtifact: (id: string, type: 'sigma' | 'kql' | 'spl') => request<DetectionValidationResult>(`/v1/validate/${type}/${id}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({}),
  }),
  simulation: (id: string, blockedTechniques: string[], options?: { scoring_mode?: 'apds' | 'rw_apds'; security_budget?: number; available_controls?: Array<{ control_id: string; control_name: string; implementation_cost: number; affected_techniques: string[]; expected_risk_reduction: number }> }) => request<SimulationResult>(`/v1/${id}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ blocked_techniques: blockedTechniques, ...options }),
  }),
  collective: (payload: unknown) => request<CollectiveDefenseResult>('/v1/collective/analyze', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  }),
  fetchCti: (payload: unknown) => request<CTIFetchResult>('/v1/cti/fetch', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  }),
  consensus: (payload: unknown) => request<ConsensusResult>('/v1/consensus/analyze', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  }),
  timeline: (id: string) => request<AttackTimeline>(`/v1/timeline/${id}`),
  importStix: (bundle: unknown) => request<unknown>('/stix/import', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(bundle),
  }),
  exportStix: (id: string) => request<unknown>(`/stix/export/${id}`),
  researchMetrics: (id: string) => request<ResearchMetricResult>(`/v1/research/metrics/${id}`),
  benchmarkReport: () => request<BenchmarkReport>('/v1/benchmark/report/summary'),
  benchmark: (id: string) => request<Record<string, unknown>>(`/v1/benchmark/${id}`),
  deleteScenario: (id: string) => request<unknown>(`/v1/scenarios/${id}`, { method: 'DELETE' }),
  notifications: () => request<Array<{ id: string; title: string; message: string; type: 'success' | 'error' | 'info'; timestamp: number; read: boolean }>>('/v1/notifications'),
  createNotification: (payload: { title: string; message: string; type: 'success' | 'error' | 'info'; read?: boolean }) => request('/v1/notifications', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) }),
  markNotificationRead: (id: string) => request(`/v1/notifications/${id}/read`, { method: 'PATCH' }),
  clearNotifications: () => request('/v1/notifications', { method: 'DELETE' }),
  exportNavigator: (id: string) => request<any>(`/v1/export/navigator/${id}`),
  exportReport: async (id: string) => {
    // using fetch directly since we need text, not JSON parsing
    const token = localStorage.getItem('tc_token');
    const response = await fetch(`/api/v1/export/report/markdown/${id}`, {
      headers: {
        'Authorization': `Bearer ${token}`
      }
    });
    if (!response.ok) throw new Error('Failed to fetch report');
    return await response.text();
  },
  copilotChat: (id: string, messages: {role: string, content: string}[]) => request<{reply: string}>(`/v1/chat/${id}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ messages })
  }, LLM_TIMEOUT_MS),
  d3fend: (id: string) => request<{ remediations: Array<{ technique_id: string, technique_name: string, countermeasures: Array<{ defensive_technique: string, rationale: string, source: string, confidence: number }> }> }>(`/v1/d3fend/${id}`),
  detectionTargets: () => request<DetectionTarget[]>('/v1/detection/targets'),
  convertScenario: (target: string, id: string) => request<ConversionResponse>(`/v1/detection/convert/${encodeURIComponent(target)}/${encodeURIComponent(id)}`),
  convertSigma: (target: string, sigma: string) => request<ConversionResponse>(`/v1/detection/convert/${encodeURIComponent(target)}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ sigma }),
  }),
  datasets: () => request<DetectionDataset[]>('/v1/detection/datasets'),
  uploadDataset: (payload: { file: File; name: string; label: 'malicious' | 'benign'; techniqueIds: string }) => {
    const form = new FormData();
    form.append('file', payload.file);
    form.append('name', payload.name);
    form.append('label', payload.label);
    form.append('technique_ids', payload.techniqueIds);
    // No Content-Type header: the browser sets the multipart boundary.
    return request<DetectionDataset>('/v1/detection/datasets', { method: 'POST', body: form }, UPLOAD_TIMEOUT_MS);
  },
  deleteDataset: (id: string) => request<unknown>(`/v1/detection/datasets/${encodeURIComponent(id)}`, { method: 'DELETE' }),
  evaluateRules: (payload: { dataset_ids: string[]; scenario_id?: string; sigma?: string }) => request<EvaluationReport>('/v1/detection/evaluate', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  }, UPLOAD_TIMEOUT_MS),
  purplePlan: (id: string, platform: string) => request<PurplePlan>(`/v1/purple/plan/${encodeURIComponent(id)}?platform=${encodeURIComponent(platform)}`),
  exportPurple: (id: string, payload: { format: 'invoke-atomic' | 'caldera'; platform: string; test_guids: string[] }) => requestFile(`/v1/purple/export/${encodeURIComponent(id)}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  }),
  createPurpleRun: (payload: { scenarioId: string; datasetId: string; platform: string; executionLog?: File | null }) => {
    const form = new FormData();
    form.append('scenario_id', payload.scenarioId);
    form.append('dataset_id', payload.datasetId);
    form.append('platform', payload.platform);
    if (payload.executionLog) form.append('execution_log', payload.executionLog);
    return request<PurpleRun>('/v1/purple/runs', { method: 'POST', body: form }, UPLOAD_TIMEOUT_MS);
  },
  purpleRuns: (scenarioId: string) => request<PurpleRun[]>(`/v1/purple/runs?scenario_id=${encodeURIComponent(scenarioId)}`),
  deletePurpleRun: (id: string) => request<unknown>(`/v1/purple/runs/${encodeURIComponent(id)}`, { method: 'DELETE' }),
  ingestAlerts: (file: File, useLlm: boolean) => {
    const form = new FormData();
    form.append('file', file);
    form.append('use_llm', String(useLlm));
    return request<AlertIngestResponse>('/v1/ingest/alerts', { method: 'POST', body: form }, LLM_TIMEOUT_MS);
  },
  ingestCti: (input: { file?: File; url?: string; text?: string }) => {
    const form = new FormData();
    if (input.file) form.append('file', input.file);
    if (input.url) form.append('url', input.url);
    if (input.text) form.append('text', input.text);
    return request<CtiIngestResponse>('/v1/ingest/cti', { method: 'POST', body: form }, LLM_TIMEOUT_MS);
  },
};
