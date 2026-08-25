import { FlaskConical } from 'lucide-react';
import { useEffect, useState } from 'react';
import { api } from '../api/client';
import { EmptyState, PageHeader, Panel, MetricCard } from '../components/common/Primitives';
import { useThreatStore } from '../store/useThreatStore';

export default function Benchmark() {
  const { scenarioId } = useThreatStore();
  const [result, setResult] = useState<any>(null);
  useEffect(() => { if (scenarioId) api.benchmark(scenarioId).then(setResult).catch(() => setResult(null)); }, [scenarioId]);
  return <div className="page-stack"><PageHeader eyebrow="Research / Benchmark" title="Benchmark" description="Backend-derived structural and ATT&CK coverage measurements for the active scenario." action={<span className="page-icon"><FlaskConical size={18} /></span>} />{result ? <><div className="metric-grid"><MetricCard label="CIR Nodes" value={result.node_count} /><MetricCard label="Graph Edges" value={result.edge_count} /><MetricCard label="Techniques" value={result.technique_count} /><MetricCard label="Coverage" value={`${result.coverage_score}%`} /></div><Panel title="Benchmark scope"><p className="prose">These measurements are derived from the active CIR and backend ATT&CK coverage analysis. They are not synthetic performance scores.</p></Panel></> : <EmptyState title="No benchmark available" description="Analyze a threat narrative first to generate benchmark measurements." />}</div>;
}
