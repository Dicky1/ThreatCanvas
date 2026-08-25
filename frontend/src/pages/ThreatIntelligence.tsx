import { useRef, useState } from 'react';
import { BrainCircuit, Download, FileUp, PlugZap, Radar, Send } from 'lucide-react';
import { api } from '../api/client';
import type { ConsensusResult, CTIFetchResult } from '../types/api';
import { EmptyState, PageHeader, Panel, StatusBadge, MetricCard } from '../components/common/Primitives';
import { useThreatStore } from '../store/useThreatStore';

const SAMPLE_CTI = {
  source_type: 'misp',
  payload: {
    Event: {
      Attribute: [
        { type: 'text', value: 'Observed T1566.001 and T1059.001 activity' },
        { type: 'domain', value: 'malicious.example' },
      ],
    },
  },
};

const SAMPLE_CONSENSUS = {
  candidates: [
    {
      model_name: 'fast-model',
      confidence: 0.82,
      cir: { attack_graph: { nodes: [{ technique: 'T1566.001' }, { technique: 'T1059.001' }] } },
    },
    {
      model_name: 'assurance-model',
      confidence: 0.91,
      cir: { attack_graph: { nodes: [{ technique: 'T1059.001' }, { technique: 'T1486' }] } },
    },
  ],
};

export default function ThreatIntelligence() {
  const scenarioId = useThreatStore((state) => state.scenarioId);
  const inputRef = useRef<HTMLInputElement>(null);
  const [message, setMessage] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [ctiPayload, setCtiPayload] = useState(JSON.stringify(SAMPLE_CTI, null, 2));
  const [ctiResult, setCtiResult] = useState<CTIFetchResult | null>(null);
  const [consensusPayload, setConsensusPayload] = useState(JSON.stringify(SAMPLE_CONSENSUS, null, 2));
  const [consensusResult, setConsensusResult] = useState<ConsensusResult | null>(null);

  async function importBundle(file: File) {
    setBusy(true);
    setMessage(null);
    try {
      const bundle = JSON.parse(await file.text());
      const result = await api.importStix(bundle);
      setMessage(`Imported STIX package${typeof result === 'object' && result && 'id' in result ? ` as ${(result as { id: string }).id}` : ''}.`);
    } catch (error) {
      setMessage(error instanceof Error ? error.message : 'Unable to import STIX bundle.');
    } finally {
      setBusy(false);
    }
  }

  async function exportScenario() {
    if (!scenarioId) return;
    setBusy(true);
    try {
      const bundle = await api.exportStix(scenarioId);
      const blob = new Blob([JSON.stringify(bundle, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = `threatcanvas-${scenarioId}.json`;
      link.click();
      URL.revokeObjectURL(url);
    } catch (error) {
      setMessage(error instanceof Error ? error.message : 'Unable to export scenario.');
    } finally {
      setBusy(false);
    }
  }

  async function fetchConnector() {
    setBusy(true);
    setMessage(null);
    try {
      setCtiResult(await api.fetchCti(JSON.parse(ctiPayload)));
    } catch (error) {
      setMessage(error instanceof Error ? error.message : 'Unable to fetch CTI connector payload.');
    } finally {
      setBusy(false);
    }
  }

  async function analyzeConsensus() {
    setBusy(true);
    setMessage(null);
    try {
      setConsensusResult(await api.consensus(JSON.parse(consensusPayload)));
    } catch (error) {
      setMessage(error instanceof Error ? error.message : 'Unable to analyze consensus.');
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="page-stack">
      <PageHeader
        eyebrow="Intelligence / CTI"
        title="Threat Intelligence"
        description="Import STIX, normalize TAXII/MISP/OpenCTI-style payloads, and compare multi-model CIR candidates before they enter analysis."
        action={<span className="page-icon"><Radar size={18} /></span>}
      />

      <Panel title="STIX exchange" description="Supported STIX objects are validated by the backend before entering the CIR.">
        <div className="action-row">
          <input ref={inputRef} type="file" accept="application/json,.json" hidden onChange={(event) => event.target.files?.[0] && importBundle(event.target.files[0])} />
          <button className="button button-primary" disabled={busy} onClick={() => inputRef.current?.click()}><FileUp size={16} /> Import STIX bundle</button>
          <button className="button button-secondary" disabled={busy || !scenarioId} onClick={exportScenario}><Download size={16} /> Export active scenario</button>
        </div>
        {message && <div className="inline-message"><StatusBadge tone={message.startsWith('Unable') ? 'danger' : 'good'}>{message.startsWith('Unable') ? 'Error' : 'Accepted'}</StatusBadge><span>{message}</span></div>}
        {!scenarioId && <EmptyState title="No active scenario" description="Export becomes available after an analysis is saved by the backend." />}
      </Panel>

      <div className="content-grid two-column">
        <Panel title="CTI connector fetch" description="Use payload mode for local tests, or provide a URL/token for TAXII, MISP, OpenCTI, or STIX JSON.">
          <textarea className="json-input" value={ctiPayload} onChange={(event) => setCtiPayload(event.target.value)} aria-label="CTI connector request JSON" />
          <div className="action-row">
            <button className="button button-secondary" disabled={busy} onClick={() => setCtiPayload(JSON.stringify(SAMPLE_CTI, null, 2))}><PlugZap size={16} /> Load sample</button>
            <button className="button button-primary" disabled={busy || !ctiPayload.trim()} onClick={fetchConnector}><Send size={16} /> Normalize CTI</button>
          </div>
        </Panel>

        <Panel title="Multi-model consensus" description="Compare CIR candidates from different model runs and separate agreed techniques from disputed ones.">
          <textarea className="json-input" value={consensusPayload} onChange={(event) => setConsensusPayload(event.target.value)} aria-label="Consensus request JSON" />
          <div className="action-row">
            <button className="button button-secondary" disabled={busy} onClick={() => setConsensusPayload(JSON.stringify(SAMPLE_CONSENSUS, null, 2))}><BrainCircuit size={16} /> Load sample</button>
            <button className="button button-primary" disabled={busy || !consensusPayload.trim()} onClick={analyzeConsensus}><Send size={16} /> Analyze consensus</button>
          </div>
        </Panel>
      </div>

      {ctiResult && (
        <Panel title="Connector result">
          <div className="metric-grid">
            <MetricCard label="Objects" value={ctiResult.object_count} />
            <MetricCard label="Techniques" value={ctiResult.technique_count} tone="good" />
            <MetricCard label="Indicators" value={ctiResult.indicator_count} />
            <MetricCard label="Source" value={ctiResult.source_type.toUpperCase()} />
          </div>
          <div className="data-list">
            {ctiResult.techniques.map((technique) => <div className="data-row" key={technique}><strong>{technique}</strong><StatusBadge tone="info">Normalized</StatusBadge></div>)}
          </div>
        </Panel>
      )}

      {consensusResult && (
        <Panel title="Consensus result">
          <div className="metric-grid">
            <MetricCard label="Models" value={consensusResult.model_count} />
            <MetricCard label="Confidence" value={`${Math.round(consensusResult.consensus_confidence * 100)}%`} tone="good" />
            <MetricCard label="Agreed" value={consensusResult.agreed_techniques.length} />
            <MetricCard label="Disputed" value={consensusResult.disputed_techniques.length} tone={consensusResult.disputed_techniques.length ? 'warn' : 'good'} />
          </div>
          <div className="data-list">
            {consensusResult.techniques.map((technique) => (
              <div className="data-row" key={technique.technique_id}>
                <div>
                  <strong>{technique.technique_id}</strong>
                  <small>{Object.entries(technique.model_votes).map(([model, confidence]) => `${model}: ${Math.round(confidence * 100)}%`).join(' | ')}</small>
                </div>
                <StatusBadge tone={consensusResult.agreed_techniques.includes(technique.technique_id) ? 'good' : 'warn'}>
                  {consensusResult.agreed_techniques.includes(technique.technique_id) ? 'Agreed' : 'Disputed'}
                </StatusBadge>
              </div>
            ))}
          </div>
        </Panel>
      )}

      {!ctiResult && !consensusResult && <EmptyState title="No CTI analysis yet" description="Normalize a connector payload or run consensus analysis to populate intelligence results." />}
    </div>
  );
}
