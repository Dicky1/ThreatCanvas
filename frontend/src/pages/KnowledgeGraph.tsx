import { Network } from 'lucide-react';
import ThreatGraph from '../components/ThreatGraph';
import { EmptyState, PageHeader, Panel } from '../components/common/Primitives';
import { useThreatStore } from '../store/useThreatStore';

export default function KnowledgeGraph() {
  const { cirData, cirSpec, scenarioId } = useThreatStore();
  return <div className="page-stack"><PageHeader eyebrow="Analysis / Knowledge Graph" title="Knowledge Graph" description="Explore CIR entities, provenance, and typed relationships from the active scenario." action={<span className="page-icon"><Network size={18} /></span>} />{cirData ? <Panel className="graph-panel"><ThreatGraph data={cirData} specification={cirSpec ?? undefined} scenarioId={scenarioId ?? undefined} /></Panel> : <EmptyState title="No knowledge graph available" description="Analyze a threat narrative first to populate the CIR knowledge graph." />}</div>;
}
