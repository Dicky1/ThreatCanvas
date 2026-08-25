import { Network } from 'lucide-react';
import KnowledgeGraphExplorer from '../components/KnowledgeGraphExplorer';
import { EmptyState, PageHeader, Panel } from '../components/common/Primitives';
import { useThreatStore } from '../store/useThreatStore';

export default function KnowledgeGraph() {
  const { cirData, cirSpec } = useThreatStore();
  return <div className="page-stack"><PageHeader eyebrow="Knowledge / Entity Explorer" title="Knowledge Graph" description="Explore security entities, provenance, typed relationships, and their links back to the active scenario." action={<span className="page-icon"><Network size={18} /></span>} />{cirData && cirSpec ? <Panel className="knowledge-panel"><KnowledgeGraphExplorer specification={cirSpec} attackGraph={cirData} /></Panel> : <EmptyState title="No knowledge graph available" description="Analyze a threat narrative first to populate entities, relationships, techniques, assets, and evidence." />}</div>;
}
