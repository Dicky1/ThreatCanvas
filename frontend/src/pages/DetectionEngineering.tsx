import { useCallback, useEffect, useMemo, useState } from 'react';
import type { FormEvent } from 'react';
import { Copy, Database, Download, FileText, FlaskConical, Trash2, Upload } from 'lucide-react';
import { api } from '../api/client';
import type {
  ConversionResponse,
  DetectionDataset,
  DetectionTarget,
  DetectionValidationResult,
  EvaluationReport,
} from '../types/api';
import { EmptyState, ErrorState, LoadingState, MetricCard, PageHeader, Panel, StatusBadge } from '../components/common/Primitives';
import { useThreatStore } from '../store/useThreatStore';

type TargetKey = 'sigma' | DetectionTarget['key'];
const message = (reason: unknown, fallback: string) => (reason instanceof Error ? reason.message : fallback);
const pct = (value: number | null | undefined) => (value === null || value === undefined ? '—' : `${(value * 100).toFixed(1)}%`);

function download(filename: string, content: string) {
  const url = URL.createObjectURL(new Blob([content], { type: 'text/plain' }));
  const link = document.createElement('a');
  link.href = url;
  link.download = filename;
  link.click();
  URL.revokeObjectURL(url);
}

const EXTENSIONS: Record<TargetKey, string> = { sigma: 'yml', splunk: 'spl', kql: 'kql', elastic: 'txt', wazuh: 'xml' };

/** A title line in each language's own comment syntax. */
function commentLine(target: TargetKey, title: string) {
  if (target === 'wazuh') return `<!-- ${title.replaceAll('--', '- -')} -->`;
  if (target === 'kql') return `// ${title}`;
  if (target === 'splunk') return `\`\`\` ${title.replaceAll('`', "'")} \`\`\``;
  return `# ${title}`;
}

/** Sigma -> SIEM conversion for the active scenario (pySigma backends). */
function ConversionPanel({ scenarioId }: { scenarioId: string }) {
  const [targets, setTargets] = useState<DetectionTarget[]>([]);
  const [target, setTarget] = useState<TargetKey>('sigma');
  const [result, setResult] = useState<ConversionResponse | null>(null);
  const [sigma, setSigma] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [copied, setCopied] = useState(false);

  useEffect(() => { api.detectionTargets().then(setTargets).catch(() => setTargets([])); }, []);
  useEffect(() => {
    setLoading(true);
    setError(null);
    // Sigma itself comes back with every conversion; splunk is the cheapest to request.
    api.convertScenario(target === 'sigma' ? 'splunk' : target, scenarioId)
      .then((response) => { setResult(response); setSigma(response.sigma ?? ''); })
      .catch((reason) => setError(message(reason, 'Unable to convert rules.')))
      .finally(() => setLoading(false));
  }, [scenarioId, target]);

  const output = target === 'sigma'
    ? sigma
    : (result?.rules ?? []).filter((rule) => rule.queries.length).map((rule) => `${commentLine(target, rule.title)}\n${rule.queries.join('\n\n')}`).join('\n\n');

  const copy = async () => {
    try { await navigator.clipboard.writeText(output); setCopied(true); window.setTimeout(() => setCopied(false), 1500); } catch { /* clipboard unavailable */ }
  };

  return (
    <Panel title="SIEM conversion" description="Sigma rules are built from the scenario's evidence fields, then converted with the official pySigma backends (Wazuh via ThreatCanvas' own converter).">
      <div className="inline-actions">
        <div className="segmented-control">
          <button className={target === 'sigma' ? 'active' : ''} onClick={() => setTarget('sigma')}>SIGMA</button>
          {targets.map((item) => <button key={item.key} title={item.description} className={target === item.key ? 'active' : ''} onClick={() => setTarget(item.key)}>{item.label}</button>)}
        </div>
        <button className="button button-quiet" onClick={copy} disabled={!output}><Copy size={14} />{copied ? 'Copied' : 'Copy'}</button>
        <button className="button button-quiet" onClick={() => download(`threatcanvas-${scenarioId}.${EXTENSIONS[target]}`, output)} disabled={!output}><Download size={14} />Download</button>
      </div>
      {loading ? <LoadingState label="Converting rules" /> : error ? <ErrorState message={error} /> : (
        <>
          <pre className="code-viewer"><code>{output || 'No detectable observable in the scenario evidence, so no rule could be generated.'}</code></pre>
          {target !== 'sigma' && result && result.errors.length > 0 && (
            <div className="data-list" style={{ marginTop: 12 }}>
              {result.errors.map((item) => <div className="data-row" key={item}><small>{item}</small><StatusBadge tone="warn">NOT CONVERTED</StatusBadge></div>)}
            </div>
          )}
        </>
      )}
    </Panel>
  );
}

/** Built-in fixture validation (syntax, schema, ATT&CK mapping, sample events). */
function QuickValidation({ scenarioId }: { scenarioId: string }) {
  const formats = ['sigma', 'kql', 'spl'] as const;
  const [format, setFormat] = useState<(typeof formats)[number]>('sigma');
  const [validation, setValidation] = useState<DetectionValidationResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    setError(null);
    api.validateArtifact(scenarioId, format).then(setValidation).catch((reason) => setError(message(reason, 'Validation failed.')));
  }, [scenarioId, format]);
  return (
    <Panel title="Quick validation" description="Structural checks plus the built-in sample events. Use datasets below for real precision/recall.">
      <div className="segmented-control">{formats.map((item) => <button key={item} className={format === item ? 'active' : ''} onClick={() => setFormat(item)}>{item.toUpperCase()}</button>)}</div>
      {error ? <ErrorState message={error} /> : validation && (
        <>
          <div className="validation-grid" style={{ marginTop: 12 }}>{Object.entries(validation.stage_results).map(([stage, passed]) => <div className="validation-item" key={stage}><span>{stage.replaceAll('_', ' ')}</span><StatusBadge tone={passed ? 'good' : 'danger'}>{passed ? 'PASS' : 'FAIL'}</StatusBadge></div>)}</div>
          <div className="validation-summary"><StatusBadge tone={validation.state === 'PRODUCTION_CANDIDATE' ? 'good' : validation.state === 'FAILED' ? 'danger' : 'warn'}>{validation.state}</StatusBadge>{validation.errors.map((item) => <span key={item}>{item}</span>)}</div>
        </>
      )}
    </Panel>
  );
}

function DatasetPanel({ datasets, onChange, selected, onToggle }: { datasets: DetectionDataset[]; onChange: () => void; selected: Set<string>; onToggle: (id: string) => void }) {
  const [file, setFile] = useState<File | null>(null);
  const [name, setName] = useState('');
  const [label, setLabel] = useState<'malicious' | 'benign'>('malicious');
  const [techniques, setTechniques] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    if (!file) return;
    setBusy(true);
    setError(null);
    try {
      await api.uploadDataset({ file, name: name || file.name, label, techniqueIds: techniques });
      setFile(null);
      setName('');
      setTechniques('');
      (event.target as HTMLFormElement).reset();
      onChange();
    } catch (reason) {
      setError(message(reason, 'Upload failed.'));
    } finally {
      setBusy(false);
    }
  };

  const remove = async (dataset: DetectionDataset) => {
    if (!window.confirm(`Delete dataset "${dataset.name}"?`)) return;
    try { await api.deleteDataset(dataset.id); onChange(); } catch (reason) { setError(message(reason, 'Delete failed.')); }
  };

  return (
    <Panel title="Log datasets" description="Upload attack recordings (OTRF Security-Datasets .zip/.tar.gz/.json, Atomic Red Team .evtx, Winlogbeat NDJSON) and benign baselines. Datasets are private to your account.">
      <form className="form-grid" onSubmit={submit}>
        <label className="span-2"><span>File (max 50 MB)</span><input type="file" accept=".json,.jsonl,.ndjson,.evtx,.zip,.gz,.tgz,.tar,.log,.txt" onChange={(e) => setFile(e.target.files?.[0] ?? null)} required /></label>
        <label><span>Name</span><input value={name} onChange={(e) => setName(e.target.value)} placeholder="e.g. empire_launcher_vbs" maxLength={120} /></label>
        <label><span>Label</span><select value={label} onChange={(e) => setLabel(e.target.value as 'malicious' | 'benign')}><option value="malicious">Malicious (attack recording)</option><option value="benign">Benign (baseline)</option></select></label>
        <label className="span-2"><span>ATT&CK techniques in this recording</span><input value={techniques} onChange={(e) => setTechniques(e.target.value)} placeholder="T1059.001, T1547.001" /></label>
        <div className="span-2 inline-actions"><button className="button button-primary" disabled={!file || busy}><Upload size={14} />{busy ? 'Uploading…' : 'Upload dataset'}</button>{error && <span className="form-error">{error}</span>}</div>
      </form>
      <div className="data-list" style={{ marginTop: 16 }}>
        {datasets.length === 0 ? <EmptyState title="No datasets yet" description="Upload a recording to measure rules against real telemetry." /> : datasets.map((dataset) => (
          <div className="data-row" key={dataset.id}>
            <label className="inline-actions" style={{ cursor: 'pointer' }}>
              <input type="checkbox" checked={selected.has(dataset.id)} onChange={() => onToggle(dataset.id)} aria-label={`Select ${dataset.name}`} />
              <div><strong>{dataset.name}</strong><small>{dataset.event_count.toLocaleString()} events · {dataset.source_filename}{dataset.technique_ids.length ? ` · ${dataset.technique_ids.join(', ')}` : ''}</small></div>
            </label>
            <div className="inline-actions"><StatusBadge tone={dataset.label === 'malicious' ? 'danger' : 'good'}>{dataset.label.toUpperCase()}</StatusBadge><button className="button button-quiet" onClick={() => remove(dataset)} aria-label={`Delete ${dataset.name}`}><Trash2 size={14} /></button></div>
          </div>
        ))}
      </div>
    </Panel>
  );
}

function EvaluationPanel({ scenarioId, selected }: { scenarioId: string | null; selected: string[] }) {
  const [source, setSource] = useState<'scenario' | 'custom'>(scenarioId ? 'scenario' : 'custom');
  const [sigma, setSigma] = useState('');
  const [report, setReport] = useState<EvaluationReport | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const run = async () => {
    setBusy(true);
    setError(null);
    try {
      setReport(await api.evaluateRules(source === 'scenario' && scenarioId ? { scenario_id: scenarioId, dataset_ids: selected } : { sigma, dataset_ids: selected }));
    } catch (reason) {
      setError(message(reason, 'Evaluation failed.'));
    } finally {
      setBusy(false);
    }
  };

  const canRun = selected.length > 0 && (source === 'scenario' ? Boolean(scenarioId) : sigma.trim().length > 0);
  return (
    <Panel title="Measure rules on datasets" description="Runs every Sigma rule against the selected datasets. Labels are per dataset, so recall is dataset-level and precision is an upper bound (attack recordings also contain normal activity).">
      <div className="inline-actions">
        <div className="segmented-control">
          <button className={source === 'scenario' ? 'active' : ''} disabled={!scenarioId} onClick={() => setSource('scenario')}>Active scenario rules</button>
          <button className={source === 'custom' ? 'active' : ''} onClick={() => setSource('custom')}>Custom Sigma</button>
        </div>
        <button className="button button-primary" onClick={run} disabled={!canRun || busy}><FlaskConical size={14} />{busy ? 'Evaluating…' : `Evaluate on ${selected.length} dataset(s)`}</button>
      </div>
      {source === 'custom' && <div className="form-grid" style={{ marginTop: 12 }}><label className="span-2"><span>Sigma rules (YAML, multiple documents allowed)</span><textarea rows={10} value={sigma} onChange={(e) => setSigma(e.target.value)} placeholder={'title: ...\nlogsource: {category: process_creation, product: windows}\ndetection: ...'} /></label></div>}
      {selected.length === 0 && <p className="form-hint" style={{ marginTop: 10 }}>Select one or more datasets above.</p>}
      {error && <ErrorState message={error} />}
      {report && (
        <div className="page-stack" style={{ marginTop: 16 }}>
          {report.truncated && <ErrorState message="Evaluation hit the 30s time budget; results are partial. Use smaller datasets or fewer rules." />}
          <div className="metric-grid">
            <MetricCard label="Dataset recall" value={pct(report.summary.dataset_recall)} detail={`${report.summary.detected_malicious_datasets}/${report.summary.malicious_datasets} attack datasets alerted`} tone={report.summary.dataset_recall === 1 ? 'good' : 'warn'} />
            <MetricCard label="Alert precision" value={pct(report.summary.alert_precision)} detail="upper bound" />
            <MetricCard label="Benign alerts" value={report.summary.benign_alerts} detail="false positives on baselines" tone={report.summary.benign_alerts ? 'danger' : 'good'} />
            <MetricCard label="Rules" value={report.summary.rules} detail={`${report.summary.rules_with_errors} not evaluable · ${report.elapsed_ms} ms`} />
          </div>
          <div className="table-scroll">
            <table className="data-table">
              <thead><tr><th>Rule</th><th>Techniques</th><th>Attack hits</th><th>Benign hits</th><th>Example match</th></tr></thead>
              <tbody>{report.rules.map((rule, index) => {
                const sample = rule.datasets.flatMap((d) => d.samples)[0];
                return (
                  <tr key={`${rule.title}-${index}`}>
                    <td>{rule.title}{rule.error && <div className="form-error">{rule.error}</div>}</td>
                    <td className="mono">{rule.techniques.join(', ') || '—'}</td>
                    <td>{rule.malicious_hits}</td>
                    <td>{rule.benign_hits ? <StatusBadge tone="danger">{rule.benign_hits}</StatusBadge> : 0}</td>
                    <td className="mono">{sample ? String(sample.CommandLine ?? sample.Image ?? sample.TargetObject ?? JSON.stringify(sample)).slice(0, 160) : '—'}</td>
                  </tr>
                );
              })}</tbody>
            </table>
          </div>
          <div className="table-scroll">
            <table className="data-table">
              <thead><tr><th>Dataset</th><th>Label</th><th>Events</th><th>Alerts</th><th>Result</th></tr></thead>
              <tbody>{report.datasets.map((dataset) => (
                <tr key={dataset.dataset_id}>
                  <td>{dataset.name}<div className="form-hint">{dataset.technique_ids.join(', ')}</div></td>
                  <td>{dataset.label}</td>
                  <td>{dataset.event_count.toLocaleString()}</td>
                  <td>{dataset.alerts}</td>
                  <td>{dataset.label === 'malicious' ? <StatusBadge tone={dataset.detected ? 'good' : 'danger'}>{dataset.detected ? 'DETECTED' : 'MISSED'}</StatusBadge> : <StatusBadge tone={dataset.alerts ? 'danger' : 'good'}>{dataset.alerts ? 'FALSE POSITIVES' : 'CLEAN'}</StatusBadge>}</td>
                </tr>
              ))}</tbody>
            </table>
          </div>
        </div>
      )}
    </Panel>
  );
}

export default function DetectionEngineering() {
  const { scenarioId } = useThreatStore();
  const [datasets, setDatasets] = useState<DetectionDataset[]>([]);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [datasetError, setDatasetError] = useState<string | null>(null);

  const loadDatasets = useCallback(() => {
    api.datasets()
      .then((rows) => {
        setDatasets(rows);
        setSelected((current) => new Set([...current].filter((id) => rows.some((row) => row.id === id))));
        setDatasetError(null);
      })
      .catch((reason) => setDatasetError(message(reason, 'Unable to load datasets.')));
  }, []);
  useEffect(loadDatasets, [loadDatasets]);

  const toggle = (id: string) => setSelected((current) => {
    const next = new Set(current);
    if (next.has(id)) next.delete(id); else next.add(id);
    return next;
  });
  const selectedIds = useMemo(() => datasets.filter((d) => selected.has(d.id)).map((d) => d.id), [datasets, selected]);

  return (
    <div className="page-stack">
      <PageHeader eyebrow="Detection / Engineering" title="Detection Engineering" description="Convert scenario rules to your SIEM and measure them against real log datasets before deployment." action={<span className="page-icon"><FileText size={18} /></span>} />
      {scenarioId ? <><ConversionPanel scenarioId={scenarioId} /><QuickValidation scenarioId={scenarioId} /></> : <EmptyState title="No active scenario" description="Analyze a scenario to convert its rules. You can still upload datasets and measure custom Sigma rules below." />}
      {datasetError ? <ErrorState message={datasetError} onRetry={loadDatasets} /> : <DatasetPanel datasets={datasets} onChange={loadDatasets} selected={selected} onToggle={toggle} />}
      <EvaluationPanel scenarioId={scenarioId} selected={selectedIds} />
      <p className="form-hint"><Database size={12} style={{ display: 'inline', marginRight: 4 }} />Datasets: <a className="underline" href="https://github.com/OTRF/Security-Datasets" target="_blank" rel="noreferrer noopener">OTRF Security-Datasets</a> · <a className="underline" href="https://github.com/redcanaryco/atomic-red-team" target="_blank" rel="noreferrer noopener">Atomic Red Team</a></p>
    </div>
  );
}
