import { useEffect, useState } from 'react';
import { Activity, ArrowRight, BarChart3, GitBranch, ShieldCheck, Target } from 'lucide-react';
import { Link } from 'react-router-dom';
import { api } from '../api/client';
import type { GraphAnalysis } from '../types/api';
import { EmptyState, ErrorState, MetricCard, PageHeader, Panel, StatusBadge } from '../components/common/Primitives';
import { useThreatStore } from '../store/useThreatStore';

export default function DashboardOverview() {
  const { cirData, scenarioId, attackVersion, coverageData, validation } = useThreatStore();
  const [analysis, setAnalysis] = useState<GraphAnalysis | null>(null);
  const [reasoning, setReasoning] = useState<Record<string, unknown> | null>(null);
  const [analysisError, setAnalysisError] = useState<string | null>(null);

  useEffect(() => {
    if (!scenarioId) {
      setAnalysis(null);
      setReasoning(null);
      return;
    }
    api.analysis(scenarioId).then(setAnalysis).catch((error) => setAnalysisError(error instanceof Error ? error.message : 'Unable to load graph analysis.'));
    api.reasoning(scenarioId).then(setReasoning).catch(() => setReasoning(null));
  }, [scenarioId]);

  const nodes = cirData?.nodes.length;
  const techniqueCount = cirData ? new Set(cirData.nodes.map((node) => node.technique)).size : undefined;
  const criticalCount = analysis?.critical_path.length;
  const riskScore = typeof reasoning?.severity_score === 'number' ? reasoning.severity_score : 'Not available';
  const severity = typeof reasoning?.severity === 'string' ? reasoning.severity : 'Not available';

  return <div className="page-stack">
    <PageHeader eyebrow="Operations / Overview" title="Security Analysis Dashboard" description="A live overview of the active threat model, detection coverage, and attack-path risk." action={<div className="dashboard-status"><Activity size={15} /> {scenarioId ? 'Scenario active' : 'Awaiting analysis'}</div>} />
    {!scenarioId ? <div className="dashboard-empty"><EmptyState title="No active scenario analyzed" description="Start with a threat narrative to populate ATT&CK mapping, graph analysis, and detection workflows." /><Link className="button button-primary" to="/threat-modeling">Open threat modeling <ArrowRight size={16} /></Link></div> : <>
      <div className="metric-grid">
        <MetricCard label="Attack nodes" value={nodes ?? 'Not available'} detail={techniqueCount !== undefined ? `${techniqueCount} unique techniques` : undefined} />
        <MetricCard label="Attack paths" value={analysis?.attack_chains?.length ?? 'Not available'} detail={analysis ? `${analysis.connected_components} connected component(s)` : 'Graph analysis loading'} />
        <MetricCard label="Detection coverage" value={coverageData ? `${coverageData.overall_score}%` : 'Not available'} tone={coverageData ? 'good' : 'neutral'} />
        <MetricCard label="Critical paths" value={criticalCount ?? 'Not available'} tone={criticalCount ? 'danger' : 'neutral'} />
        <MetricCard label="Current risk" value={riskScore} detail={`Severity: ${severity}`} tone={typeof riskScore === 'number' && riskScore >= 70 ? 'danger' : 'neutral'} />
        <MetricCard label="APDS / RW-APDS" value="Not available" detail="Run a defense simulation" />
      </div>
      {analysisError && <ErrorState message={analysisError} onRetry={() => scenarioId && api.analysis(scenarioId).then(setAnalysis).catch(() => setAnalysisError('Unable to load graph analysis.'))} />}
      <div className="content-grid two-column">
        <Panel title="Current scenario" description="Values are sourced from the active CIR and backend analysis."><div className="scenario-summary"><div><span className="summary-label">Scenario ID</span><strong className="mono">{scenarioId}</strong></div><div><span className="summary-label">ATT&CK version</span><strong>{attackVersion || 'Not available'}</strong></div><div><span className="summary-label">CIR validation</span><StatusBadge tone={validation?.valid ? 'good' : validation ? 'danger' : 'warn'}>{validation ? (validation.valid ? 'VALID' : 'FAILED') : 'NOT AVAILABLE'}</StatusBadge></div></div></Panel>
        <Panel title="Risk signals" description="Simulation metrics appear after a real defense simulation run."><div className="signal-list"><div><Target size={16} /><span>Current risk</span><strong>{riskScore}</strong></div><div><GitBranch size={16} /><span>APDS / RW-APDS</span><strong>Not available</strong></div><div><ShieldCheck size={16} /><span>Critical path</span><strong>{analysis?.critical_path.length ? `${analysis.critical_path.length} nodes` : 'Not available'}</strong></div></div></Panel>
      </div>
      <Panel title="Continue analysis"><div className="quick-links"><Link to="/threat-modeling"><BarChart3 size={17} /><span><strong>Threat modeling</strong><small>Review CIR, evidence, and validation</small></span><ArrowRight size={16} /></Link><Link to="/detection"><ShieldCheck size={17} /><span><strong>Detection engineering</strong><small>Inspect generated rules and validation</small></span><ArrowRight size={16} /></Link><Link to="/simulation"><GitBranch size={17} /><span><strong>Defense simulation</strong><small>Run a what-if analysis on the graph</small></span><ArrowRight size={16} /></Link></div></Panel>
    </>}
  </div>;
}
