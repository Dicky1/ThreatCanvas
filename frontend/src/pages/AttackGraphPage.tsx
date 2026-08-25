import { useEffect, useState } from 'react';
import { Network } from 'lucide-react';
import ThreatGraph from '../components/ThreatGraph';
import { EmptyState, PageHeader, Panel } from '../components/common/Primitives';
import { useThreatStore } from '../store/useThreatStore';
import { api } from '../api/client';
import type { GraphAnalysis } from '../types/api';

export default function AttackGraphPage() {
  const { cirData, cirSpec, scenarioId } = useThreatStore();
  const [analysis, setAnalysis] = useState<GraphAnalysis | null>(null);
  useEffect(() => { if (scenarioId) api.analysis(scenarioId).then(setAnalysis).catch(() => setAnalysis(null)); }, [scenarioId]);
  const pathNodes = analysis?.critical_path.map((id) => cirData?.nodes.find((node) => node.step_id === id)).filter(Boolean) ?? [];
  const highRiskIds = new Set((analysis?.high_risk_nodes ?? []).map((node) => node.node_id));
  return <div className="page-stack"><PageHeader eyebrow="Analysis / Graph" title="Attack Graph" description="Explore relationships, critical paths, and high-risk nodes from the active scenario." action={<span className="page-icon"><Network size={18} /></span>} />{cirData ? <><Panel className="graph-panel"><ThreatGraph data={cirData} specification={cirSpec ?? undefined} scenarioId={scenarioId ?? undefined} /></Panel>{analysis?.critical_path.length ? <Panel title="Critical path" description="The backend currently returns the longest ordered attack chain; risk weighting is shown only where supplied by analysis."><div className="data-list"><div className="workflow">{pathNodes.map((node, index) => <span key={node?.step_id}>{node?.action_type || node?.technique}{index < pathNodes.length - 1 && <i>→</i>}</span>)}</div><div className="metric-grid"><div className="metric-card"><span>Path nodes</span><strong>{analysis.critical_path.length}</strong></div><div className="metric-card"><span>High-risk nodes</span><strong>{analysis.critical_path.filter((id) => highRiskIds.has(id)).length}</strong></div><div className="metric-card"><span>Graph coverage</span><strong>{analysis.coverage_percentage}%</strong></div><div className="metric-card"><span>Kill-chain completion</span><strong>{analysis.kill_chain_completion}%</strong></div></div></div></Panel> : null}</> : <EmptyState title="No attack graph available" description="Analyze a threat narrative first to populate the graph workspace." />}</div>;
}
