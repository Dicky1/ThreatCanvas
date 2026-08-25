import { useEffect, useMemo, useState } from 'react';
import { FlaskConical } from 'lucide-react';
import { api } from '../api/client';
import { EmptyState, ErrorState, LoadingState, MetricCard, PageHeader, Panel, StatusBadge } from '../components/common/Primitives';
import { useThreatStore } from '../store/useThreatStore';
import type { BenchmarkReport, ExperimentRun } from '../types/api';

function percent(value?: number) {
  return typeof value === 'number' ? `${value.toFixed(1)}%` : 'Not available';
}

function numberMetric(value: unknown) {
  return typeof value === 'number' ? value.toFixed(1) : 'Not available';
}

function latestDetailNumber(runs: ExperimentRun[], key: string) {
  for (const run of [...runs].reverse()) {
    const value = run.details?.[key];
    if (typeof value === 'number') return value;
  }
  return undefined;
}

export default function ResearchMetrics() {
  const { cirData, coverageData, scenarioId, validation } = useThreatStore();
  const [runs, setRuns] = useState<ExperimentRun[]>([]);
  const [benchmark, setBenchmark] = useState<BenchmarkReport | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    async function load() {
      setLoading(true);
      setError(null);
      try {
        const [benchmarkResult, metricResult] = await Promise.all([
          api.benchmarkReport(),
          scenarioId ? api.researchMetrics(scenarioId).catch(() => null) : Promise.resolve(null),
        ]);
        if (!cancelled) {
          setBenchmark(benchmarkResult);
          setRuns(metricResult?.runs ?? []);
        }
      } catch (reason) {
        if (!cancelled) {
          setError(reason instanceof Error ? reason.message : 'Failed to load research metrics.');
          setBenchmark(null);
          setRuns([]);
        }
      } finally {
        if (!cancelled) setLoading(false);
      }
    }
    load();
    return () => { cancelled = true; };
  }, [scenarioId]);

  const latest = runs[runs.length - 1];
  const meanLatency = useMemo(() => {
    if (!runs.length) return undefined;
    return runs.reduce((total, run) => total + run.duration_ms, 0) / runs.length;
  }, [runs]);
  const p95Latency = useMemo(() => {
    if (!runs.length) return undefined;
    const sorted = [...runs].sort((a, b) => a.duration_ms - b.duration_ms);
    return sorted[Math.max(0, Math.ceil(sorted.length * 0.95) - 1)]?.duration_ms;
  }, [runs]);
  const detectionPrecision = latestDetailNumber(runs, 'detection_precision');
  const detectionRecall = latestDetailNumber(runs, 'detection_recall');
  const detectionF1 = latestDetailNumber(runs, 'detection_f1');
  const apds = latestDetailNumber(runs, 'apds');
  const rwApds = latestDetailNumber(runs, 'rw_apds');

  return (
    <div className="page-stack">
      <PageHeader
        eyebrow="Research / Evaluation"
        title="Research Metrics"
        description="Experiment telemetry, benchmark fixtures, and reproducibility signals for ThreatCanvas research runs."
        action={<span className="page-icon"><FlaskConical size={18} /></span>}
      />

      {loading && <LoadingState label="Loading research metrics" />}
      {error && <ErrorState message={error} />}

      <Panel title="Evaluation dataset" description="Current bundled benchmark is a demonstration fixture, not a large unseen narrative corpus.">
        {benchmark ? (
          <>
            <div className="metric-grid">
              <MetricCard label="Scenarios" value={benchmark.summary.scenario_count} />
              <MetricCard label="CIR validity" value={percent(benchmark.summary.cir_validity_rate)} tone="good" />
              <MetricCard label="ATT&CK F1" value={percent(benchmark.summary.attack_f1)} tone="good" />
              <MetricCard label="Graph ordering" value={percent(benchmark.summary.graph_ordering_accuracy)} tone="good" />
            </div>
            <div className="research-note">
              These numbers come from curated benchmark fixtures. For paper claims, run the same evaluator against human-labelled unseen narratives.
            </div>
          </>
        ) : (
          <EmptyState title="No benchmark report" description="Generate benchmark/results/report.json to show reproducible evaluation fixtures." />
        )}
      </Panel>

      <div className="two-column">
        <Panel title="ATT&CK mapping">
          <div className="metric-grid metric-grid-compact">
            <MetricCard label="Precision" value={percent(benchmark?.summary.attack_precision)} />
            <MetricCard label="Recall" value={percent(benchmark?.summary.attack_recall)} />
            <MetricCard label="F1" value={percent(benchmark?.summary.attack_f1)} />
            <MetricCard label="Tactic recall" value={percent(benchmark?.summary.tactic_recall)} />
          </div>
        </Panel>

        <Panel title="CIR">
          <div className="metric-grid metric-grid-compact">
            <MetricCard label="Schema validity" value={percent(benchmark?.summary.cir_validity_rate)} />
            <MetricCard label="Nodes" value={cirData?.nodes.length ?? 'Not available'} />
            <MetricCard label="Edges" value={cirData?.edges.length ?? 'Not available'} />
            <MetricCard label="Validation" value={validation?.valid ? 'Valid' : 'Not available'} tone={validation?.valid ? 'good' : 'neutral'} />
          </div>
        </Panel>
      </div>

      <div className="two-column">
        <Panel title="Detection">
          <div className="metric-grid metric-grid-compact">
            <MetricCard label="Coverage" value={coverageData ? `${coverageData.overall_score}%` : 'Not available'} tone={coverageData ? 'good' : 'neutral'} />
            <MetricCard label="Precision" value={percent(detectionPrecision)} />
            <MetricCard label="Recall" value={percent(detectionRecall)} />
            <MetricCard label="F1" value={percent(detectionF1)} />
          </div>
          <div className="research-note">Detection scores are available when validation runs record TP/FP/TN/FN-derived details.</div>
        </Panel>

        <Panel title="Performance">
          <div className="metric-grid metric-grid-compact">
            <MetricCard label="Runs" value={runs.length || 'Not available'} />
            <MetricCard label="Mean latency" value={meanLatency ? `${meanLatency.toFixed(0)} ms` : 'Not available'} />
            <MetricCard label="P95 latency" value={p95Latency ? `${p95Latency.toFixed(0)} ms` : 'Not available'} />
            <MetricCard label="Latest status" value={latest?.status ?? 'Not available'} />
          </div>
        </Panel>
      </div>

      <Panel title="Defense">
        <div className="metric-grid">
          <MetricCard label="APDS" value={numberMetric(apds)} />
          <MetricCard label="RW-APDS" value={numberMetric(rwApds)} />
          <MetricCard label="Covered techniques" value={coverageData?.covered_techniques.length ?? 'Not available'} />
          <MetricCard label="Missing tactics" value={coverageData?.missing_tactics.length ?? 'Not available'} tone={coverageData?.missing_tactics.length ? 'warn' : 'neutral'} />
        </div>
      </Panel>

      <Panel title="Experiment runs">
        {runs.length ? (
          <div className="data-list">
            {runs.slice(-6).reverse().map((run) => (
              <div className="data-row" key={`${run.operation}-${run.created_at}`}>
                <div>
                  <strong>{run.operation}</strong>
                  <small>{run.node_count ?? 0} nodes | {run.edge_count ?? 0} edges | {run.duration_ms.toFixed(0)} ms</small>
                </div>
                <StatusBadge tone={run.status === 'success' ? 'good' : 'warn'}>{run.status}</StatusBadge>
              </div>
            ))}
          </div>
        ) : (
          <EmptyState title="No scenario telemetry yet" description="Run a scenario analysis to record backend operation timing and validation metadata." />
        )}
      </Panel>
    </div>
  );
}
