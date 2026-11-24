import { FlaskConical, Play } from 'lucide-react';
import { useCallback, useEffect, useMemo, useState } from 'react';
import { api } from '../api/client';
import type { BenchmarkCase, BenchmarkRun, LLMProfileInfo } from '../types/api';
import { EmptyState, ErrorState, LoadingState, MetricCard, PageHeader, Panel, StatusBadge } from '../components/common/Primitives';
import { useThreatStore } from '../store/useThreatStore';

const pct = (value: number | undefined) => (value === undefined ? '—' : `${(value * 100).toFixed(0)}%`);
const message = (reason: unknown, fallback: string) => (reason instanceof Error ? reason.message : fallback);

function ScenarioMetrics() {
  const { scenarioId } = useThreatStore();
  const [result, setResult] = useState<Record<string, number> | null>(null);
  useEffect(() => { if (scenarioId) api.benchmark(scenarioId).then((r) => setResult(r as Record<string, number>)).catch(() => setResult(null)); }, [scenarioId]);
  if (!result) return null;
  return (
    <Panel title="Active scenario" description="Structural and ATT&CK coverage measurements derived from the active CIR.">
      <div className="metric-grid"><MetricCard label="CIR Nodes" value={result.node_count} /><MetricCard label="Graph Edges" value={result.edge_count} /><MetricCard label="Techniques" value={result.technique_count} /><MetricCard label="Coverage" value={`${result.coverage_score}%`} /></div>
    </Panel>
  );
}

function RunReport({ run, cases }: { run: BenchmarkRun; cases: BenchmarkCase[] }) {
  const [detail, setDetail] = useState<string | null>(null);
  if (!run.report) return null;
  const entries = Object.entries(run.report.profiles);
  const caseTitle = (id: string) => cases.find((c) => c.id === id)?.title ?? id;
  return (
    <div className="page-stack" style={{ marginTop: 14 }}>
      <div className="table-scroll">
        <table className="data-table">
          <thead><tr><th>Model</th><th>Cases</th><th>Valid CIR</th><th>Technique F1</th><th>Precision</th><th>Recall</th><th>Parent F1</th><th>Ordering</th><th>Avg repairs</th><th>Avg latency</th></tr></thead>
          <tbody>{entries.map(([name, data]) => (
            <tr key={name}>
              <td className="mono">{name}</td>
              <td>{data.summary.cases}/{run.report?.cases.length}</td>
              <td>{pct(data.summary.valid_rate)}</td>
              <td><strong>{pct(data.summary.exact_f1)}</strong></td>
              <td>{pct(data.summary.exact_precision)}</td>
              <td>{pct(data.summary.exact_recall)}</td>
              <td>{pct(data.summary.parent_f1)}</td>
              <td>{pct(data.summary.ordering)}</td>
              <td>{data.summary.avg_repair_attempts.toFixed(2)}</td>
              <td>{(data.summary.avg_latency_ms / 1000).toFixed(1)}s</td>
            </tr>
          ))}</tbody>
        </table>
      </div>
      <div className="segmented-control">{entries.map(([name]) => <button key={name} className={detail === name ? 'active' : ''} onClick={() => setDetail(detail === name ? null : name)}>{name}: per case</button>)}</div>
      {detail && run.report.profiles[detail] && (
        <div className="table-scroll">
          <table className="data-table">
            <thead><tr><th>Case</th><th>Status</th><th>F1</th><th>Ordering</th><th>Missing</th><th>Extra</th><th>Repairs</th></tr></thead>
            <tbody>{run.report.profiles[detail].results.map((r) => (
              <tr key={r.case_id}>
                <td>{caseTitle(r.case_id)}{r.error && <div className="form-error">{r.error}</div>}</td>
                <td><StatusBadge tone={r.status === 'valid' ? 'good' : 'danger'}>{r.status.toUpperCase()}</StatusBadge></td>
                <td>{pct(r.exact.f1)}</td>
                <td>{pct(r.ordering)}</td>
                <td className="mono">{r.missing.join(', ') || '—'}</td>
                <td className="mono">{r.extra.join(', ') || '—'}</td>
                <td>{r.repair_attempts}</td>
              </tr>
            ))}</tbody>
          </table>
        </div>
      )}
    </div>
  );
}

function ModelBenchmark() {
  const [cases, setCases] = useState<BenchmarkCase[]>([]);
  const [profiles, setProfiles] = useState<LLMProfileInfo[]>([]);
  const [chosen, setChosen] = useState<Set<string>>(new Set());
  const [subset, setSubset] = useState<Set<string>>(new Set());
  const [runs, setRuns] = useState<BenchmarkRun[]>([]);
  const [current, setCurrent] = useState<BenchmarkRun | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api.benchmarkCases().then(setCases).catch(() => setCases([]));
    api.llmProfiles().then((r) => { setProfiles(r.profiles); setChosen(new Set([r.default])); }).catch(() => setProfiles([]));
  }, []);
  const loadRuns = useCallback(() => {
    api.benchmarkRuns().then((rows) => {
      setRuns(rows);
      if (rows[0]) api.benchmarkRun(rows[0].id).then((run) => setCurrent((c) => c ?? run)).catch(() => undefined);
    }).catch(() => setRuns([]));
  }, []);
  useEffect(loadRuns, [loadRuns]);

  // Poll the active run until it finishes.
  const activeId = current && (current.status === 'queued' || current.status === 'running') ? current.id : null;
  useEffect(() => {
    if (!activeId) return;
    const timer = window.setInterval(() => {
      api.benchmarkRun(activeId).then((run) => { setCurrent(run); if (run.status === 'done' || run.status === 'failed') loadRuns(); }).catch(() => undefined);
    }, 3000);
    return () => window.clearInterval(timer);
  }, [activeId, loadRuns]);

  const toggle = (set: Set<string>, update: (s: Set<string>) => void, value: string) => {
    const next = new Set(set);
    if (next.has(value)) next.delete(value); else next.add(value);
    update(next);
  };
  const start = async () => {
    setError(null);
    try { setCurrent(await api.startBenchmark([...chosen], [...subset])); } catch (reason) { setError(message(reason, 'Unable to start the benchmark.')); }
  };
  const calls = useMemo(() => chosen.size * (subset.size || cases.length), [chosen, subset, cases]);

  return (
    <Panel title="Model benchmark" description="Run the bundled narratives through the full pipeline (with self-repair) for each selected model and compare ATT&CK accuracy against ground truth.">
      <div className="form-grid">
        <div className="span-2">
          <span className="form-hint">Models</span>
          <div className="chip-row" style={{ marginTop: 6 }}>{profiles.map((p) => (
            <label key={p.name} className="inline-actions" style={{ fontSize: '.78rem', color: '#b7cbd4' }}><input type="checkbox" checked={chosen.has(p.name)} onChange={() => toggle(chosen, setChosen, p.name)} aria-label={`Benchmark ${p.name}`} />{p.name}{p.local ? ' (local)' : ''} <span className="form-hint">{p.mode}</span></label>
          ))}</div>
          {profiles.length < 2 && <p className="form-hint">Configure several models with LLM_PROFILES in the backend .env to compare them (e.g. a cloud model and a local Ollama model).</p>}
        </div>
        <div className="span-2">
          <span className="form-hint">Cases ({subset.size || cases.length} of {cases.length}; none selected = all)</span>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(260px, 1fr))', gap: 4, marginTop: 6 }}>{cases.map((c) => (
            <label key={c.id} className="inline-actions" style={{ fontSize: '.74rem', color: '#b7cbd4' }} title={c.narrative}><input type="checkbox" checked={subset.has(c.id)} onChange={() => toggle(subset, setSubset, c.id)} />{c.title}</label>
          ))}</div>
        </div>
        <div className="span-2 inline-actions">
          <button className="button button-primary" onClick={start} disabled={!chosen.size || Boolean(activeId)}><Play size={14} />{activeId ? 'Running…' : `Run benchmark (~${calls}–${calls * 3} LLM calls)`}</button>
          {error && <span className="form-error">{error}</span>}
        </div>
      </div>
      {current && (
        <div style={{ marginTop: 14 }}>
          <div className="inline-actions"><StatusBadge tone={current.status === 'done' ? 'good' : current.status === 'failed' ? 'danger' : 'info'}>{current.status.toUpperCase()}</StatusBadge><span className="form-hint">{new Date(current.created_at).toLocaleString()} · {current.profiles.join(', ')}</span></div>
          {current.error && <ErrorState message={current.error} />}
          {activeId && !current.report && <LoadingState label="Running narratives through the models" />}
          <RunReport run={current} cases={cases} />
        </div>
      )}
      {runs.length > 1 && (
        <div className="data-list" style={{ marginTop: 14 }}>
          {runs.slice(0, 10).map((run) => (
            <button key={run.id} className="data-row text-left" onClick={() => api.benchmarkRun(run.id).then(setCurrent)}>
              <div><strong>{new Date(run.created_at).toLocaleString()}</strong><small>{Object.entries(run.summary ?? {}).map(([name, s]) => `${name}: F1 ${pct(s.exact_f1)}`).join(' · ') || run.profiles.join(', ')}</small></div>
              <StatusBadge tone={run.status === 'done' ? 'good' : run.status === 'failed' ? 'danger' : 'info'}>{run.status.toUpperCase()}</StatusBadge>
            </button>
          ))}
        </div>
      )}
    </Panel>
  );
}

export default function Benchmark() {
  const { scenarioId } = useThreatStore();
  return (
    <div className="page-stack">
      <PageHeader eyebrow="Research / Benchmark" title="Benchmark" description="Compare LLMs on ATT&CK extraction accuracy, and inspect the active scenario." action={<span className="page-icon"><FlaskConical size={18} /></span>} />
      <ModelBenchmark />
      {scenarioId ? <ScenarioMetrics /> : <EmptyState title="No active scenario" description="Analyze a narrative to see its structural measurements." />}
    </div>
  );
}
