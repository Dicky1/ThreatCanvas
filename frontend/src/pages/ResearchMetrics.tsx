import { FlaskConical } from 'lucide-react';
import { PageHeader, Panel, MetricCard, EmptyState } from '../components/common/Primitives';
import { useThreatStore } from '../store/useThreatStore';
import { useEffect, useState } from 'react';
import { api } from '../api/client';

export default function ResearchMetrics() {
  const { cirData, coverageData, scenarioId } = useThreatStore();
  const [runs, setRuns] = useState<Array<{ operation: string; duration_ms: number; status: string; details: Record<string, unknown> }>>([]);
  useEffect(() => { if (scenarioId) api.researchMetrics(scenarioId).then((data) => setRuns(data.runs)).catch(() => setRuns([])); }, [scenarioId]);
  const available = Boolean(cirData || coverageData);
  const latest = runs[runs.length - 1];
  return <div className="page-stack"><PageHeader eyebrow="Research / Evaluation" title="Research Metrics" description="Backend-backed measurements for reproducible threat-modeling experiments." action={<span className="page-icon"><FlaskConical size={18} /></span>} />{available ? <><div className="metric-grid"><MetricCard label="CIR Nodes" value={cirData?.nodes.length ?? 'Not available'} /><MetricCard label="Graph Edges" value={cirData?.edges.length ?? 'Not available'} /><MetricCard label="Coverage" value={coverageData ? `${coverageData.overall_score}%` : 'Not available'} tone={coverageData ? 'good' : 'neutral'} /><MetricCard label="Parse Time" value={latest ? `${latest.duration_ms.toFixed(0)} ms` : 'Not available'} detail={latest ? latest.status : 'Run a scenario first'} /></div><Panel title="Experiment support"><p className="prose">{runs.length ? `Backend recorded ${runs.length} experiment run(s). Latest operation: ${latest?.operation ?? 'unknown'}.` : 'Run a scenario analysis to record processing time and validation status.'}</p></Panel></> : <EmptyState title="No research run available" description="Run a scenario analysis to display supported graph and coverage measurements." />}</div>;
}
