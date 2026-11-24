import { useCallback, useEffect, useMemo, useState } from 'react';
import type { FormEvent } from 'react';
import { Download, Swords, Trash2, Upload } from 'lucide-react';
import { Link } from 'react-router-dom';
import { api } from '../api/client';
import type { DetectionDataset, PurplePlan, PurpleRun, PurpleStatus } from '../types/api';
import { EmptyState, ErrorState, LoadingState, MetricCard, PageHeader, Panel, StatusBadge } from '../components/common/Primitives';
import { useThreatStore } from '../store/useThreatStore';

const message = (reason: unknown, fallback: string) => (reason instanceof Error ? reason.message : fallback);
const STATUS_TONE: Record<PurpleStatus, 'good' | 'danger' | 'warn' | 'neutral' | 'info'> = {
  DETECTED: 'good',
  MISSED: 'danger',
  NO_RULE: 'warn',
  NOT_EXECUTED: 'neutral',
  UNVERIFIED: 'info',
};
const STATUS_HELP: Record<PurpleStatus, string> = {
  DETECTED: 'Rules for this technique alerted on the captured telemetry',
  MISSED: 'Executed successfully but no rule alerted',
  NO_RULE: 'No rule could be generated from the scenario evidence',
  NOT_EXECUTED: 'Execution log shows the test did not run successfully',
  UNVERIFIED: 'No alert and no execution log to confirm the test ran',
};

function saveFile(blob: Blob, filename: string) {
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = filename;
  link.click();
  URL.revokeObjectURL(url);
}

function PlanPanel({ scenarioId, platform, setPlatform }: { scenarioId: string; platform: string; setPlatform: (p: string) => void }) {
  const [plan, setPlan] = useState<PurplePlan | null>(null);
  const [chosen, setChosen] = useState<Set<string>>(new Set());
  const [error, setError] = useState<string | null>(null);
  const [exporting, setExporting] = useState<string | null>(null);

  useEffect(() => {
    setPlan(null);
    setError(null);
    api.purplePlan(scenarioId, platform)
      .then((result) => {
        setPlan(result);
        // Default: first atomic test of every step.
        setChosen(new Set(result.steps.flatMap((step) => step.tests.slice(0, 1).map((test) => test.guid))));
      })
      .catch((reason) => setError(message(reason, 'Unable to build the plan.')));
  }, [scenarioId, platform]);

  const toggle = (guid: string) => setChosen((current) => {
    const next = new Set(current);
    if (next.has(guid)) next.delete(guid); else next.add(guid);
    return next;
  });

  const exportAs = async (format: 'invoke-atomic' | 'caldera') => {
    setExporting(format);
    setError(null);
    try {
      const { blob, filename } = await api.exportPurple(scenarioId, { format, platform, test_guids: [...chosen] });
      saveFile(blob, filename);
    } catch (reason) {
      setError(message(reason, 'Export failed.'));
    } finally {
      setExporting(null);
    }
  };

  return (
    <Panel title="1 · Plan the emulation" description="Atomic Red Team tests mapped to each scenario technique. Choose the tests, then export for Invoke-AtomicRedTeam or Caldera. Run only in an isolated lab you are authorized to test.">
      <div className="inline-actions">
        <div className="segmented-control">{['windows', 'linux', 'macos'].map((item) => <button key={item} className={platform === item ? 'active' : ''} onClick={() => setPlatform(item)}>{item}</button>)}</div>
        <button className="button button-primary" disabled={!chosen.size || exporting !== null} onClick={() => exportAs('invoke-atomic')}><Download size={14} />{exporting === 'invoke-atomic' ? 'Exporting…' : 'PowerShell (Invoke-AtomicRedTeam)'}</button>
        <button className="button button-secondary" disabled={!chosen.size || exporting !== null} onClick={() => exportAs('caldera')}><Download size={14} />{exporting === 'caldera' ? 'Exporting…' : 'Caldera bundle (.zip)'}</button>
        <span className="form-hint">{chosen.size} test(s) selected</span>
      </div>
      {error && <ErrorState message={error} />}
      {!plan ? !error && <LoadingState label="Mapping techniques to atomic tests" /> : (
        <div className="data-list" style={{ marginTop: 14 }}>
          {plan.steps.map((step) => (
            <div className="data-row" key={step.step_id} style={{ alignItems: 'flex-start' }}>
              <div style={{ minWidth: 0, flex: 1 }}>
                <strong>{step.step_id} · {step.technique} {step.technique_name ? `— ${step.technique_name}` : ''}</strong>
                {step.tests.length === 0 ? <small>No Atomic Red Team test for this technique on {platform}.</small> : (
                  <div style={{ display: 'grid', gap: 4, marginTop: 8 }}>
                    {step.from_parent && <small>Using tests of the parent technique {step.technique.split('.')[0]}.</small>}
                    {step.tests.slice(0, 8).map((test) => (
                      <label key={test.guid} className="inline-actions" style={{ fontSize: '.74rem', color: '#b7cbd4' }}>
                        <input type="checkbox" checked={chosen.has(test.guid)} onChange={() => toggle(test.guid)} aria-label={`Select ${test.name}`} />
                        #{test.test_number} {test.name} <span className="form-hint">({test.executor})</span>
                      </label>
                    ))}
                    {step.tests.length > 8 && <small>+{step.tests.length - 8} more tests</small>}
                  </div>
                )}
              </div>
              <StatusBadge tone={step.tests.length ? 'good' : 'warn'}>{step.tests.length ? `${step.tests.length} TESTS` : 'NO ATOMIC'}</StatusBadge>
            </div>
          ))}
        </div>
      )}
    </Panel>
  );
}

function RunResult({ run }: { run: PurpleRun }) {
  return (
    <div className="page-stack" style={{ marginTop: 14 }}>
      {run.summary.truncated && <ErrorState message="Evaluation hit the time budget; results are partial." />}
      <div className="metric-grid">
        <MetricCard label="Detection rate" value={run.summary.detection_rate === null ? '—' : `${(run.summary.detection_rate * 100).toFixed(0)}%`} detail="executed techniques with rules" tone={run.summary.detection_rate === 1 ? 'good' : 'warn'} />
        <MetricCard label="Detected" value={run.summary.detected} tone="good" />
        <MetricCard label="Missed" value={run.summary.missed} tone={run.summary.missed ? 'danger' : 'neutral'} />
        <MetricCard label="No rule" value={run.summary.no_rule} detail={run.summary.execution_log ? `${run.summary.executions} executions logged` : 'no execution log'} />
      </div>
      <div className="table-scroll">
        <table className="data-table">
          <thead><tr><th>Technique</th><th>Tactic</th><th>Rules</th><th>Alerts</th><th>Executed</th><th>Result</th></tr></thead>
          <tbody>{run.techniques.map((row) => (
            <tr key={row.technique}>
              <td className="mono">{row.technique}<div className="form-hint">{row.technique_name}</div></td>
              <td>{row.tactic}</td>
              <td>{row.rules}</td>
              <td>{row.alerts}</td>
              <td>{row.executed === null ? '—' : row.executed ? 'yes' : 'no'}</td>
              <td title={STATUS_HELP[row.status]}><StatusBadge tone={STATUS_TONE[row.status]}>{row.status.replace('_', ' ')}</StatusBadge></td>
            </tr>
          ))}</tbody>
        </table>
      </div>
    </div>
  );
}

function ResultsPanel({ scenarioId, platform }: { scenarioId: string; platform: string }) {
  const [datasets, setDatasets] = useState<DetectionDataset[]>([]);
  const [datasetId, setDatasetId] = useState('');
  const [logFile, setLogFile] = useState<File | null>(null);
  const [runs, setRuns] = useState<PurpleRun[]>([]);
  const [current, setCurrent] = useState<PurpleRun | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const loadRuns = useCallback(() => {
    api.purpleRuns(scenarioId).then((rows) => { setRuns(rows); setCurrent((c) => c ?? rows[0] ?? null); }).catch(() => setRuns([]));
  }, [scenarioId]);
  useEffect(() => {
    setCurrent(null);
    api.datasets().then((rows) => { setDatasets(rows); setDatasetId((id) => id || rows[0]?.id || ''); }).catch(() => setDatasets([]));
    loadRuns();
  }, [loadRuns]);

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const run = await api.createPurpleRun({ scenarioId, datasetId, platform, executionLog: logFile });
      setCurrent(run);
      loadRuns();
    } catch (reason) {
      setError(message(reason, 'Unable to process the results.'));
    } finally {
      setBusy(false);
    }
  };

  const remove = async (run: PurpleRun) => {
    if (!window.confirm('Delete this run?')) return;
    try {
      await api.deletePurpleRun(run.id);
      if (current?.id === run.id) setCurrent(null);
      loadRuns();
    } catch (reason) {
      setError(message(reason, 'Delete failed.'));
    }
  };

  const selected = useMemo(() => datasets.find((d) => d.id === datasetId), [datasets, datasetId]);
  return (
    <Panel title="2 · Import results" description="Upload the Sysmon / event logs captured during the run as a dataset (Detection Engineering page), pick it here, and optionally add the execution log so missed detections can be told apart from tests that never ran.">
      {datasets.length === 0 ? (
        <EmptyState title="No telemetry dataset yet" description="Upload the logs captured during execution on the Detection Engineering page first." />
      ) : (
        <form className="form-grid" onSubmit={submit}>
          <label><span>Telemetry dataset</span><select value={datasetId} onChange={(e) => setDatasetId(e.target.value)}>{datasets.map((d) => <option key={d.id} value={d.id}>{d.name} ({d.event_count.toLocaleString()} events)</option>)}</select></label>
          <label><span>Execution log (optional)</span><input type="file" accept=".csv,.json" onChange={(e) => setLogFile(e.target.files?.[0] ?? null)} /></label>
          <p className="form-hint span-2">Invoke-AtomicTest CSV (the generated script writes threatcanvas-execution-log.csv) or a Caldera operation report (JSON).{selected?.label === 'benign' ? ' Note: the selected dataset is labelled benign.' : ''}</p>
          <div className="span-2 inline-actions"><button className="button button-primary" disabled={!datasetId || busy}><Upload size={14} />{busy ? 'Matching…' : 'Match rules against telemetry'}</button>{error && <span className="form-error">{error}</span>}</div>
        </form>
      )}
      <p className="form-hint" style={{ marginTop: 10 }}><Link className="underline" to="/detection">Open Detection Engineering to upload datasets →</Link></p>
      {current && <RunResult run={current} />}
      {runs.length > 1 && (
        <div className="data-list" style={{ marginTop: 16 }}>
          {runs.map((run) => (
            <div className="data-row" key={run.id}>
              <button className="text-left" onClick={() => setCurrent(run)}><strong>{new Date(run.created_at).toLocaleString()}</strong><small>{run.dataset_name} · {run.summary.detected}/{run.summary.techniques} detected</small></button>
              <div className="inline-actions">{current?.id === run.id && <StatusBadge tone="info">SHOWN</StatusBadge>}<button className="button button-quiet" aria-label="Delete run" onClick={() => remove(run)}><Trash2 size={14} /></button></div>
            </div>
          ))}
        </div>
      )}
    </Panel>
  );
}

export default function PurpleTeam() {
  const { scenarioId } = useThreatStore();
  const [platform, setPlatform] = useState('windows');
  return (
    <div className="page-stack">
      <PageHeader eyebrow="Validation / Purple Team" title="Purple Team Loop" description="Emulate the scenario with Atomic Red Team or Caldera, then check which techniques the generated rules really detected." action={<span className="page-icon"><Swords size={18} /></span>} />
      {!scenarioId ? <EmptyState title="No active scenario" description="Analyze a scenario first; its techniques become the emulation plan." /> : (
        <>
          <PlanPanel scenarioId={scenarioId} platform={platform} setPlatform={setPlatform} />
          <ResultsPanel scenarioId={scenarioId} platform={platform} />
        </>
      )}
    </div>
  );
}
