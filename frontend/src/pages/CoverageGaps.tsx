import { useCallback, useEffect, useMemo, useState } from 'react';
import type { FormEvent } from 'react';
import { Download, Radar, Save, Trash2, Upload } from 'lucide-react';
import { api } from '../api/client';
import type { DataSourceState, GapAnalysis, GapStatus, InventorySummary } from '../types/api';
import { EmptyState, ErrorState, LoadingState, MetricCard, PageHeader, Panel, StatusBadge } from '../components/common/Primitives';
import { useThreatStore } from '../store/useThreatStore';

const message = (reason: unknown, fallback: string) => (reason instanceof Error ? reason.message : fallback);
const STATUS: Record<GapStatus, { label: string; tone: 'good' | 'warn' | 'danger' | 'info' | 'neutral'; help: string }> = {
  COVERED: { label: 'COVERED', tone: 'good', help: 'An existing rule targets it and the data it needs is collected' },
  COVERED_UNVERIFIED_TELEMETRY: { label: 'RULE (DATA UNKNOWN)', tone: 'info', help: 'An existing rule targets it; configure data sources to verify telemetry' },
  RULE_WITHOUT_TELEMETRY: { label: 'RULE, NO DATA', tone: 'warn', help: 'A rule exists but none of the data components it needs is collected' },
  TELEMETRY_WITHOUT_RULE: { label: 'DATA, NO RULE', tone: 'warn', help: 'The telemetry is collected but no rule detects it yet' },
  BLIND: { label: 'BLIND', tone: 'danger', help: 'No rule and none of the required data is collected' },
  NO_RULE: { label: 'NO RULE', tone: 'danger', help: 'No existing rule (data sources not configured)' },
};

function InventoryPanel({ summary, onChange }: { summary: InventorySummary | null; onChange: () => void }) {
  const [file, setFile] = useState<File | null>(null);
  const [replace, setReplace] = useState(false);
  const [busy, setBusy] = useState(false);
  const [note, setNote] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    if (!file) return;
    setBusy(true);
    setError(null);
    setNote(null);
    try {
      const result = await api.importInventory(file, replace);
      setNote(`Imported ${result.imported} rules${result.skipped_untagged ? `, skipped ${result.skipped_untagged} without ATT&CK tags` : ''}.`);
      onChange();
    } catch (reason) {
      setError(message(reason, 'Import failed.'));
    } finally {
      setBusy(false);
    }
  };

  const clear = async () => {
    if (!window.confirm('Remove every imported rule?')) return;
    try { await api.clearInventory(); onChange(); } catch (reason) { setError(message(reason, 'Delete failed.')); }
  };

  return (
    <Panel title="1 · Existing detection rules" description="Import the rules you already run: Sigma files or a .zip of your rules repository (ATT&CK tags like attack.t1059.001 are used), or a CSV (technique, title) exported from any SIEM.">
      <form className="form-grid" onSubmit={submit}>
        <label className="span-2"><span>Rules (.yml, .yaml, .zip, .csv · max 30 MB)</span><input type="file" accept=".yml,.yaml,.zip,.csv" onChange={(e) => setFile(e.target.files?.[0] ?? null)} /></label>
        <label className="span-2 inline-actions" style={{ display: 'flex' }}><input type="checkbox" checked={replace} onChange={(e) => setReplace(e.target.checked)} style={{ width: 'auto', minHeight: 0 }} /><span style={{ textTransform: 'none', letterSpacing: 0, fontSize: '.78rem' }}>Replace the current inventory</span></label>
        <div className="span-2 inline-actions">
          <button className="button button-primary" disabled={!file || busy}><Upload size={14} />{busy ? 'Importing…' : 'Import rules'}</button>
          {summary && summary.rules > 0 && <button type="button" className="button button-quiet" onClick={clear}><Trash2 size={14} />Clear inventory</button>}
          {note && <span className="form-hint">{note}</span>}
          {error && <span className="form-error">{error}</span>}
        </div>
      </form>
      {summary && (
        <div className="metric-grid" style={{ marginTop: 14 }}>
          <MetricCard label="Rules in inventory" value={summary.rules.toLocaleString()} />
          <MetricCard label="Techniques covered by rules" value={summary.techniques} />
          <MetricCard label="Most covered" value={summary.top_techniques[0]?.[0] ?? '—'} detail={summary.top_techniques[0] ? `${summary.top_techniques[0][1]} rules` : undefined} />
        </div>
      )}
    </Panel>
  );
}

function DataSourcePanel({ state, onChange }: { state: DataSourceState | null; onChange: () => void }) {
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [filter, setFilter] = useState('');
  const [busy, setBusy] = useState(false);
  const [note, setNote] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => { setSelected(new Set(state?.components ?? [])); }, [state]);

  const toggle = (name: string) => setSelected((current) => {
    const next = new Set(current);
    if (next.has(name)) next.delete(name); else next.add(name);
    return next;
  });
  const save = async () => {
    setBusy(true);
    setError(null);
    try { await api.saveDataSources([...selected]); setNote('Saved.'); onChange(); } catch (reason) { setError(message(reason, 'Save failed.')); } finally { setBusy(false); }
  };
  const importDettect = async (file: File | undefined) => {
    if (!file) return;
    setBusy(true);
    setError(null);
    try {
      const result = await api.importDettect(file);
      setNote(`Imported ${result.components.length} available data components from DeTT&CT${result.unmatched.length ? `; not matched to ATT&CK: ${result.unmatched.join(', ')}` : ''}.`);
      onChange();
    } catch (reason) {
      setError(message(reason, 'Import failed.'));
    } finally {
      setBusy(false);
    }
  };

  const visible = useMemo(() => (state?.catalog ?? []).filter((name) => name.toLowerCase().includes(filter.toLowerCase())), [state, filter]);
  return (
    <Panel title="2 · Data sources you collect" description="Tick the ATT&CK data components your SIEM actually receives, or import a DeTT&CT data source administration file.">
      {!state ? <LoadingState label="Loading data components" /> : (
        <>
          <div className="inline-actions">
            <label className="button button-secondary" style={{ cursor: 'pointer' }}><Upload size={14} />Import DeTT&CT YAML<input type="file" accept=".yaml,.yml" hidden onChange={(e) => importDettect(e.target.files?.[0])} /></label>
            <button className="button button-primary" onClick={save} disabled={busy}><Save size={14} />Save selection ({selected.size})</button>
            <StatusBadge tone={state.configured ? 'good' : 'warn'}>{state.configured ? `CONFIGURED (${state.source})` : 'NOT CONFIGURED'}</StatusBadge>
            {note && <span className="form-hint">{note}</span>}
            {error && <span className="form-error">{error}</span>}
          </div>
          <div className="form-grid" style={{ marginTop: 12 }}><label className="span-2"><span>Filter</span><input value={filter} onChange={(e) => setFilter(e.target.value)} placeholder="process, registry, network…" /></label></div>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(230px, 1fr))', gap: 6, marginTop: 12, maxHeight: 280, overflow: 'auto' }}>
            {visible.map((name) => (
              <label key={name} className="inline-actions" style={{ fontSize: '.75rem', color: '#b7cbd4' }}>
                <input type="checkbox" checked={selected.has(name)} onChange={() => toggle(name)} aria-label={name} />{name}
              </label>
            ))}
          </div>
        </>
      )}
    </Panel>
  );
}

function AnalysisPanel({ scenarioId, refreshKey }: { scenarioId: string; refreshKey: number }) {
  const [analysis, setAnalysis] = useState<GapAnalysis | null>(null);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    setError(null);
    api.gapAnalysis(scenarioId).then(setAnalysis).catch((reason) => setError(message(reason, 'Analysis failed.')));
  }, [scenarioId, refreshKey]);

  const exportLayer = async () => {
    try {
      const layer = await api.gapNavigator(scenarioId);
      const url = URL.createObjectURL(new Blob([JSON.stringify(layer, null, 2)], { type: 'application/json' }));
      const link = document.createElement('a');
      link.href = url;
      link.download = `threatcanvas-gaps-${scenarioId}.json`;
      link.click();
      URL.revokeObjectURL(url);
    } catch (reason) {
      setError(message(reason, 'Export failed.'));
    }
  };

  if (error) return <Panel title="3 · Gap analysis"><ErrorState message={error} /></Panel>;
  if (!analysis) return <Panel title="3 · Gap analysis"><LoadingState label="Comparing with your environment" /></Panel>;
  const s = analysis.summary;
  return (
    <Panel title="3 · Gap analysis for the active scenario" description="Real coverage: your existing rules and collected telemetry, not theoretical ATT&CK mapping.">
      <div className="inline-actions"><button className="button button-quiet" onClick={exportLayer}><Download size={14} />ATT&CK Navigator layer</button></div>
      {(!s.data_source_profile || s.inventory_rules === 0) && <p className="form-hint" style={{ marginTop: 8 }}>{s.inventory_rules === 0 ? 'No rules imported yet. ' : ''}{!s.data_source_profile ? 'Data sources not configured, so telemetry cannot be verified.' : ''}</p>}
      <div className="metric-grid" style={{ marginTop: 12 }}>
        <MetricCard label="Real coverage" value={s.coverage === null ? '—' : `${Math.round(s.coverage * 100)}%`} detail={`${s.covered}/${s.techniques} techniques`} tone={s.coverage === 1 ? 'good' : 'warn'} />
        <MetricCard label="Blind spots" value={s.blind} tone={s.blind ? 'danger' : 'good'} />
        <MetricCard label="Rules without data" value={s.rule_without_telemetry} tone={s.rule_without_telemetry ? 'warn' : 'neutral'} />
        <MetricCard label="Data without rules" value={s.telemetry_without_rule} detail="quick wins" />
      </div>
      {analysis.top_missing_data_components.length > 0 && (
        <div style={{ marginTop: 14 }}>
          <p className="form-hint">Collect these first (techniques they would make detectable):</p>
          <div className="chip-row">{analysis.top_missing_data_components.map((item) => <StatusBadge key={item.data_component} tone="warn">{item.data_component} · {item.techniques}</StatusBadge>)}</div>
        </div>
      )}
      <div className="table-scroll" style={{ marginTop: 14 }}>
        <table className="data-table">
          <thead><tr><th>Technique</th><th>Status</th><th>Your rules</th><th>Missing data</th><th>Log sources (ATT&CK)</th></tr></thead>
          <tbody>{analysis.techniques.map((row) => (
            <tr key={row.technique}>
              <td className="mono">{row.technique}<div className="form-hint">{row.technique_name}</div></td>
              <td title={STATUS[row.status].help}><StatusBadge tone={STATUS[row.status].tone}>{STATUS[row.status].label}</StatusBadge>{row.status === 'TELEMETRY_WITHOUT_RULE' && row.generated_rule_available && <div className="form-hint">ThreatCanvas generated a rule: see Detection Engineering</div>}</td>
              <td>{row.existing_rule_count ? row.existing_rules.slice(0, 3).map((rule) => <div key={rule.title}>{rule.title}{rule.match === 'related' && <span className="form-hint"> (parent/sub)</span>}</div>) : '—'}</td>
              <td>{row.missing_data_components.join(', ') || '—'}</td>
              <td className="form-hint">{row.log_sources.slice(0, 4).join(', ') || '—'}</td>
            </tr>
          ))}</tbody>
        </table>
      </div>
    </Panel>
  );
}

export default function CoverageGaps() {
  const { scenarioId } = useThreatStore();
  const [summary, setSummary] = useState<InventorySummary | null>(null);
  const [dataSources, setDataSources] = useState<DataSourceState | null>(null);
  const [refreshKey, setRefreshKey] = useState(0);
  const [error, setError] = useState<string | null>(null);

  const reload = useCallback(() => {
    Promise.all([api.inventorySummary(), api.dataSources()])
      .then(([inventory, sources]) => { setSummary(inventory); setDataSources(sources); setRefreshKey((k) => k + 1); setError(null); })
      .catch((reason) => setError(message(reason, 'Unable to load your environment.')));
  }, []);
  useEffect(reload, [reload]);

  return (
    <div className="page-stack">
      <PageHeader eyebrow="Detection / Gap Analysis" title="Coverage Gaps" description="Compare a scenario with the rules you already run and the logs you actually collect (DeTT&CT style)." action={<span className="page-icon"><Radar size={18} /></span>} />
      {error && <ErrorState message={error} onRetry={reload} />}
      <InventoryPanel summary={summary} onChange={reload} />
      <DataSourcePanel state={dataSources} onChange={reload} />
      {scenarioId ? <AnalysisPanel scenarioId={scenarioId} refreshKey={refreshKey} /> : <EmptyState title="No active scenario" description="Analyze or load a scenario to see its real coverage gaps." />}
    </div>
  );
}
