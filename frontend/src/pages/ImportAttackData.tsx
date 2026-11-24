import { useState } from 'react';
import type { FormEvent } from 'react';
import { FileInput, Siren } from 'lucide-react';
import { useNavigate } from 'react-router-dom';
import { ApiError, api } from '../api/client';
import type { AlertIngestResponse, CtiIngestResponse, RepairAttempt } from '../types/api';
import { PageHeader, Panel, StatusBadge } from '../components/common/Primitives';
import ModelSelect from '../components/ModelSelect';
import { useThreatStore } from '../store/useThreatStore';

function describeError(reason: unknown): string {
  if (reason instanceof ApiError && reason.detail && typeof reason.detail === 'object' && 'repair_attempts' in reason.detail) {
    const attempts = (reason.detail as { repair_attempts: RepairAttempt[] }).repair_attempts;
    return `The AI output still failed validation after ${attempts.length} attempt(s). Try a shorter or more specific source.`;
  }
  return reason instanceof Error ? reason.message : 'Import failed.';
}

function CtiPanel() {
  const navigate = useNavigate();
  const loadParseResult = useThreatStore((state) => state.loadParseResult);
  const [mode, setMode] = useState<'url' | 'file' | 'text'>('url');
  const [url, setUrl] = useState('');
  const [file, setFile] = useState<File | null>(null);
  const [text, setText] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<CtiIngestResponse | null>(null);

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const response = await api.ingestCti(mode === 'url' ? { url } : mode === 'file' && file ? { file } : { text }, useThreatStore.getState().modelProfile);
      setResult(response);
      await loadParseResult(response, `[CTI report] ${response.source.title || response.source.location}`);
    } catch (reason) {
      setError(describeError(reason));
    } finally {
      setBusy(false);
    }
  };

  const ready = mode === 'url' ? /^https?:\/\//i.test(url.trim()) : mode === 'file' ? Boolean(file) : text.trim().length > 80;
  return (
    <Panel title="Threat intelligence report → CIR" description="Turn a vendor blog, advisory or PDF report into an attack graph. URLs are fetched server-side with SSRF protection (public addresses only).">
      <div className="segmented-control">
        {(['url', 'file', 'text'] as const).map((item) => <button key={item} className={mode === item ? 'active' : ''} onClick={() => setMode(item)}>{item === 'url' ? 'URL' : item === 'file' ? 'PDF / HTML file' : 'Paste text'}</button>)}
      </div>
      <form className="form-grid" style={{ marginTop: 12 }} onSubmit={submit}>
        {mode === 'url' && <label className="span-2"><span>Report URL</span><input type="url" value={url} onChange={(e) => setUrl(e.target.value)} placeholder="https://vendor.example/blog/apt-campaign" /></label>}
        {mode === 'file' && <label className="span-2"><span>Report file (PDF, HTML, TXT, MD · max 20 MB)</span><input type="file" accept=".pdf,.html,.htm,.txt,.md" onChange={(e) => setFile(e.target.files?.[0] ?? null)} /></label>}
        {mode === 'text' && <label className="span-2"><span>Report text</span><textarea rows={10} value={text} onChange={(e) => setText(e.target.value)} placeholder="Paste the report body…" /></label>}
        <p className="form-hint span-2">Long reports are truncated to the first ~30,000 characters for the AI. Scanned (image-only) PDFs are not supported.</p>
        <div className="span-2 inline-actions">
          <button className="button button-primary" disabled={!ready || busy}><FileInput size={14} />{busy ? 'Extracting attack chain…' : 'Build attack graph'}</button>
          {error && <span className="form-error">{error}</span>}
        </div>
      </form>
      {result && (
        <div className="data-row" style={{ marginTop: 14 }}>
          <div><strong>{result.source.title || result.source.location}</strong><small>{result.cir.attack_graph.nodes.length} steps · {result.source.characters.toLocaleString()} characters{result.source.truncated ? ' (truncated)' : ''}{result.repair_attempts.length ? ` · self-repaired ${result.repair_attempts.length}x` : ''}</small></div>
          <button className="button button-secondary" onClick={() => navigate('/threat-modeling')}>Open in Threat Modeling</button>
        </div>
      )}
    </Panel>
  );
}

function AlertPanel() {
  const navigate = useNavigate();
  const loadParseResult = useThreatStore((state) => state.loadParseResult);
  const [file, setFile] = useState<File | null>(null);
  const [useLlm, setUseLlm] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<AlertIngestResponse | null>(null);

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    if (!file) return;
    setBusy(true);
    setError(null);
    try {
      const response = await api.ingestAlerts(file, useLlm, useThreatStore.getState().modelProfile);
      setResult(response);
      await loadParseResult(response, `[SIEM alerts] ${file.name}`);
    } catch (reason) {
      setError(describeError(reason));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Panel title="SIEM / EDR alerts → CIR" description="Reconstruct the attack chain from an incident's alerts for triage. Alerts carrying ATT&CK technique ids are converted deterministically (no AI); others can optionally be reconstructed by the AI.">
      <form className="form-grid" onSubmit={submit}>
        <label className="span-2"><span>Alert export (JSON / JSON lines · max 20 MB)</span><input type="file" accept=".json,.jsonl,.ndjson,.txt" onChange={(e) => setFile(e.target.files?.[0] ?? null)} /></label>
        <p className="form-hint span-2">Supported: Wazuh alerts.json, Elastic Security detection alerts (search hits / NDJSON), Microsoft Sentinel / Defender (API "value" arrays), Splunk ES notable exports, generic JSON with ATT&CK fields.</p>
        <label className="span-2 inline-actions" style={{ display: 'flex' }}><input type="checkbox" checked={useLlm} onChange={(e) => setUseLlm(e.target.checked)} style={{ width: 'auto', minHeight: 0 }} /><span style={{ textTransform: 'none', letterSpacing: 0, fontSize: '.78rem' }}>Reconstruct with AI when alerts carry no ATT&CK technique ids</span></label>
        <div className="span-2 inline-actions">
          <button className="button button-primary" disabled={!file || busy}><Siren size={14} />{busy ? 'Building graph…' : 'Build attack graph'}</button>
          {error && <span className="form-error">{error}</span>}
        </div>
      </form>
      {result && (
        <div className="data-row" style={{ marginTop: 14 }}>
          <div>
            <strong>{result.cir.attack_graph.nodes.length} attack steps from {result.stats.alerts} alerts</strong>
            <small>{result.stats.alerts_with_techniques} alerts mapped to ATT&CK{result.stats.skipped_techniques.length ? ` · unknown/deprecated ids skipped: ${result.stats.skipped_techniques.join(', ')}` : ''}</small>
          </div>
          <div className="inline-actions"><StatusBadge tone={result.method === 'deterministic' ? 'good' : 'info'}>{result.method === 'deterministic' ? 'DETERMINISTIC' : 'AI RECONSTRUCTED'}</StatusBadge><button className="button button-secondary" onClick={() => navigate('/threat-modeling')}>Open in Threat Modeling</button></div>
        </div>
      )}
    </Panel>
  );
}

export default function ImportAttackData() {
  return (
    <div className="page-stack">
      <PageHeader eyebrow="Ingest / Reverse" title="Import Attack Data" description="Start from real data instead of a narrative: CTI reports or SIEM alerts become a CIR scenario you can analyze, detect and simulate." action={<div className="inline-actions"><ModelSelect /><span className="page-icon"><FileInput size={18} /></span></div>} />
      <AlertPanel />
      <CtiPanel />
    </div>
  );
}
