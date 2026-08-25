import { useMemo, useState } from 'react';
import { Background, Controls, ReactFlow } from 'reactflow';
import 'reactflow/dist/style.css';
import { DatabaseZap, FileJson, Send, Users } from 'lucide-react';
import { api } from '../api/client';
import type { CollectiveDefenseResult } from '../types/api';
import { EmptyState, ErrorState, LoadingState, MetricCard, PageHeader, Panel, StatusBadge } from '../components/common/Primitives';

const SAMPLE_PACKAGE = {
  packages: [
    {
      package_id: 'org-a-ransomware',
      organization: { organization_id: 'org-a', name: 'Organization A' },
      tlp: 'TLP:GREEN',
      source_confidence: 0.86,
      observed_techniques: ['T1566.001', 'T1059.001', 'T1003', 'T1021.002'],
      detected_techniques: ['T1566.001', 'T1059.001'],
      sanitized_indicators: [{ type: 'domain', value: 'malicious.example' }],
      provenance: 'sanitized incident report A',
    },
    {
      package_id: 'org-b-lateral',
      organization: { organization_id: 'org-b', name: 'Organization B' },
      tlp: 'TLP:AMBER',
      source_confidence: 0.78,
      observed_techniques: ['T1059.001', 'T1003', 'T1021.002', 'T1486'],
      detected_techniques: ['T1003', 'T1486'],
      sanitized_indicators: [{ type: 'sha256', value: 'REDACTED_SAMPLE_HASH' }],
      provenance: 'sanitized SOC package B',
    },
  ],
  local_detected_techniques: ['T1059.001'],
};

type PackageForm = {
  organization: string;
  organizationId: string;
  tlp: 'TLP:CLEAR' | 'TLP:GREEN' | 'TLP:AMBER';
  confidence: number;
  observedTechniques: string;
  detectedTechniques: string;
  localDetectedTechniques: string;
  indicatorType: string;
  indicatorValue: string;
};

const DEFAULT_FORM: PackageForm = {
  organization: 'Organization A',
  organizationId: 'org-a',
  tlp: 'TLP:GREEN',
  confidence: 86,
  observedTechniques: 'T1566.001, T1059.001, T1003, T1021.002, T1486',
  detectedTechniques: 'T1566.001, T1059.001, T1486',
  localDetectedTechniques: 'T1059.001',
  indicatorType: 'domain',
  indicatorValue: 'malicious.example',
};

function parseList(value: string) {
  return value.split(/[\s,]+/).map((item) => item.trim().toUpperCase()).filter(Boolean);
}

function CollectiveThreatGraph({ result }: { result: CollectiveDefenseResult }) {
  const graph = result.collective_graph;
  const nodes = useMemo(() => graph.nodes.map((node, index) => ({
    id: node.technique_id,
    data: { label: `${node.technique_id}\n${node.observed_by_count} source(s)` },
    position: { x: (index % 4) * 240, y: Math.floor(index / 4) * 145 },
    style: {
      background: node.emerging ? '#2a2214' : '#122532',
      border: `1px solid ${node.emerging ? '#735c35' : '#315a70'}`,
      color: node.emerging ? '#f0d08a' : '#dff3fb',
      borderRadius: 6,
      fontSize: 12,
      whiteSpace: 'pre-line',
      width: 170,
    },
  })), [graph.nodes]);
  const edges = useMemo(() => graph.edges.map((edge) => ({
    id: `${edge.source}-${edge.target}`,
    source: edge.source,
    target: edge.target,
    label: `${Math.round(edge.confidence * 100)}%`,
    animated: edge.observed_by_count > 1,
    style: { stroke: edge.observed_by_count > 1 ? '#e4b568' : '#6f8794' },
  })), [graph.edges]);

  if (!nodes.length) {
    return <EmptyState title="No collective graph available" description="Submit packages with observed techniques to build a shared threat graph." />;
  }

  return (
    <div className="collective-graph">
      <ReactFlow nodes={nodes} edges={edges} fitView>
        <Background />
        <Controls />
      </ReactFlow>
    </div>
  );
}

export default function CollectiveDefense() {
  const [payload, setPayload] = useState('');
  const [form, setForm] = useState<PackageForm>(DEFAULT_FORM);
  const [advanced, setAdvanced] = useState(false);
  const [result, setResult] = useState<CollectiveDefenseResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const formPayload = useMemo(() => ({
    packages: [
      {
        package_id: `${form.organizationId || 'org'}-manual`,
        organization: {
          organization_id: form.organizationId || 'org-manual',
          name: form.organization || 'Manual Organization',
        },
        tlp: form.tlp,
        source_confidence: Math.max(0, Math.min(form.confidence, 100)) / 100,
        observed_techniques: parseList(form.observedTechniques),
        detected_techniques: parseList(form.detectedTechniques),
        sanitized_indicators: form.indicatorValue.trim()
          ? [{ type: form.indicatorType.trim() || 'indicator', value: form.indicatorValue.trim() }]
          : [],
        provenance: 'manual collective defense import',
      },
    ],
    local_detected_techniques: parseList(form.localDetectedTechniques),
  }), [form]);

  async function analyze() {
    setLoading(true);
    setError(null);
    try {
      setResult(await api.collective(advanced ? JSON.parse(payload) : formPayload));
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : 'Collective analysis failed.');
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="page-stack">
      <PageHeader
        eyebrow="Collective / Correlation"
        title="Collective Defense"
        description="Shared, sanitized intelligence transformed into correlated defensive knowledge and a collective threat graph."
        action={<span className="page-icon"><Users size={18} /></span>}
      />
      <Panel title="Submit sanitized intelligence" description="The backend enforces TLP and package validation. Do not paste organization-sensitive data.">
        {!advanced ? (
          <div className="collective-form">
            <label>
              <span>Organization</span>
              <input value={form.organization} onChange={(event) => setForm({ ...form, organization: event.target.value })} />
            </label>
            <label>
              <span>Organization ID</span>
              <input value={form.organizationId} onChange={(event) => setForm({ ...form, organizationId: event.target.value })} />
            </label>
            <label>
              <span>TLP</span>
              <select value={form.tlp} onChange={(event) => setForm({ ...form, tlp: event.target.value as PackageForm['tlp'] })}>
                <option>TLP:GREEN</option>
                <option>TLP:CLEAR</option>
                <option>TLP:AMBER</option>
              </select>
            </label>
            <label>
              <span>Confidence</span>
              <input type="number" min="0" max="100" value={form.confidence} onChange={(event) => setForm({ ...form, confidence: Number(event.target.value) })} />
            </label>
            <label className="span-2">
              <span>Observed techniques</span>
              <input value={form.observedTechniques} onChange={(event) => setForm({ ...form, observedTechniques: event.target.value })} />
            </label>
            <label className="span-2">
              <span>Detected techniques</span>
              <input value={form.detectedTechniques} onChange={(event) => setForm({ ...form, detectedTechniques: event.target.value })} />
            </label>
            <label>
              <span>Indicator type</span>
              <input value={form.indicatorType} onChange={(event) => setForm({ ...form, indicatorType: event.target.value })} />
            </label>
            <label>
              <span>Indicator value</span>
              <input value={form.indicatorValue} onChange={(event) => setForm({ ...form, indicatorValue: event.target.value })} />
            </label>
            <label className="span-2">
              <span>Local detected techniques</span>
              <input value={form.localDetectedTechniques} onChange={(event) => setForm({ ...form, localDetectedTechniques: event.target.value })} />
            </label>
          </div>
        ) : (
          <textarea
            className="json-input"
            value={payload}
            onChange={(event) => setPayload(event.target.value)}
            placeholder={'{"packages": [], "local_detected_techniques": []}'}
            aria-label="Sanitized threat intelligence package JSON"
          />
        )}
        <div className="action-row">
          <button className="button button-secondary" disabled={loading} onClick={() => { setPayload(JSON.stringify(SAMPLE_PACKAGE, null, 2)); setAdvanced(true); }}>
            <DatabaseZap size={16} /> Load sample
          </button>
          <button className="button button-secondary" disabled={loading} onClick={() => setAdvanced(!advanced)}>
            <FileJson size={16} /> {advanced ? 'Form mode' : 'Advanced JSON'}
          </button>
          <button className="button button-primary" disabled={loading || (advanced && !payload.trim())} onClick={analyze}>
            <Send size={16} /> Analyze package
          </button>
        </div>
        {loading && <LoadingState label="Correlating shared intelligence" />}
        {error && <ErrorState message={error} />}
      </Panel>

      {result ? (
        <>
          <div className="metric-grid">
            <MetricCard label="Sources" value={new Set(result.shared_techniques.flatMap((item) => item.source_packages)).size} />
            <MetricCard label="Observed techniques" value={result.coverage.observed_techniques.length} />
            <MetricCard label="Local coverage" value={`${result.coverage.local_coverage}%`} />
            <MetricCard label="Collective coverage" value={`${result.coverage.collective_coverage}%`} tone={result.coverage.detection_gap_techniques.length ? 'warn' : 'good'} detail={`${result.coverage.collective_detected_techniques.length} detected by union`} />
          </div>
          {result.coverage.detection_gap_techniques.length > 0 && (
            <Panel title="Collective detection gaps" description="Observed techniques not covered by the union of submitted organizational detections.">
              <div className="chip-row">
                {result.coverage.detection_gap_techniques.map((technique) => <StatusBadge key={technique} tone="warn">{technique}</StatusBadge>)}
              </div>
            </Panel>
          )}
          <Panel title="Collective threat graph" description="Edges are inferred from ordered techniques shared by sanitized packages; animated edges were observed by more than one package.">
            <CollectiveThreatGraph result={result} />
          </Panel>
          <Panel title="Shared attack paths">
            <div className="data-list">
              {result.shared_attack_paths.length ? result.shared_attack_paths.map((path) => (
                <div className="data-row" key={path.techniques.join('-')}>
                  <div>
                    <strong>{path.techniques.join(' -> ')}</strong>
                    <small>{path.source_packages.length} source package(s)</small>
                  </div>
                  <StatusBadge tone="info">Confidence {Math.round(path.confidence * 100)}%</StatusBadge>
                </div>
              )) : <EmptyState title="No shared paths" description="No ordered attack path was returned by the backend." />}
            </div>
          </Panel>
          <Panel title="Recommended controls" description="Controls are returned only when the backend has explicit mappings for shared techniques.">
            <div className="data-list">
              {Object.entries(result.recommended_controls).length ? Object.entries(result.recommended_controls).map(([technique, controls]) => (
                <div className="data-row" key={technique}>
                  <div>
                    <strong>{technique}</strong>
                    <small>{controls.join(', ')}</small>
                  </div>
                  <StatusBadge tone="warn">Coverage gap</StatusBadge>
                </div>
              )) : <EmptyState title="No mapped controls" description="No explicit control mapping was returned for the shared techniques." />}
            </div>
          </Panel>
        </>
      ) : <EmptyState title="No collective analysis yet" description="Provide a sanitized package payload or load the sample package to build a collective threat graph." />}
    </div>
  );
}
