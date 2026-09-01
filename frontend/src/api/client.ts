import type {
  CIRSpecification,
  CollectiveDefenseResult,
  CoverageReport,
  AttackTimeline,
  BenchmarkReport,
  ConsensusResult,
  CTIFetchResult,
  DetectionValidationResult,
  GraphAnalysis,
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

  constructor(status: number, message: string) {
    super(message);
    this.status = status;
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

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const controller = new AbortController();
  const timeout = window.setTimeout(() => controller.abort(), 20_000);
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
      const detail = typeof body === 'object' && body !== null && 'detail' in body
        ? formatErrorDetail((body as { detail: unknown }).detail)
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
      throw new ApiError(response.status, detail);
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

export const api = {
  health: () => fetch('/health').then((response) => {
    if (!response.ok) throw new ApiError(response.status, 'Backend health check failed');
    return response.json() as Promise<{ status: string }>;
  }),
  parse: (scenario: string) => request<{ cir: CIRSpecification; validation: Record<string, unknown>; id: string }>('/v1/parse', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ scenario }),
  }),
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
};
