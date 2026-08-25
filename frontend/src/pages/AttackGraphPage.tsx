import { useEffect, useState } from 'react';
import { Network } from 'lucide-react';
import ThreatGraph from '../components/ThreatGraph';
import AttackTimelinePlayer from '../components/AttackTimelinePlayer';
import { EmptyState, PageHeader, Panel, StatusBadge } from '../components/common/Primitives';
import { useThreatStore } from '../store/useThreatStore';
import { api } from '../api/client';
import type { AttackTimeline, GraphAnalysis } from '../types/api';
import { groupPathByTrustZone } from '../utils/trustZones';

export default function AttackGraphPage() {
  const { cirData, scenarioId } = useThreatStore();
  const [analysis, setAnalysis] = useState<GraphAnalysis | null>(null);
  const [timeline, setTimeline] = useState<AttackTimeline | null>(null);

  useEffect(() => {
    if (scenarioId) {
      api.analysis(scenarioId).then(setAnalysis).catch(() => setAnalysis(null));
      api.timeline(scenarioId).then(setTimeline).catch(() => setTimeline(null));
    }
  }, [scenarioId]);

  const pathNodes = analysis?.critical_path
    .map((id) => cirData?.nodes.find((node) => node.step_id === id))
    .filter(Boolean) ?? [];
  const highRiskIds = new Set((analysis?.high_risk_nodes ?? []).map((node) => node.node_id));
  const topAssetRisks = [...(analysis?.asset_risk_signals ?? [])]
    .filter((signal) => signal.risk_score >= 60 || signal.crown_jewel_exposure > 0 || signal.asset_criticality >= 0.8)
    .sort((left, right) => right.risk_score - left.risk_score)
    .slice(0, 4);
  const trustZones = groupPathByTrustZone(pathNodes);

  return (
    <div className="page-stack">
      <PageHeader
        eyebrow="Analysis / Graph"
        title="Attack Graph"
        description="Explore ordered attack paths, critical nodes, choke points, and asset-aware risk signals from the active scenario."
        action={<span className="page-icon"><Network size={18} /></span>}
      />

      {cirData ? (
        <>
          <Panel className="graph-panel">
            <ThreatGraph data={cirData} scenarioId={scenarioId ?? undefined} />
          </Panel>

          {analysis?.critical_path.length ? (
            <Panel
              title="Critical path explainer"
              description="Deterministic reasoning derived from graph topology, detection context, high-risk tactics, asset criticality, and trust-boundary metadata."
            >
              <div className="data-list">
                <div className="workflow">
                  {pathNodes.map((node, index) => (
                    <span key={node?.step_id}>
                      {node?.action_type || node?.technique}
                      {index < pathNodes.length - 1 && <i>{'->'}</i>}
                    </span>
                  ))}
                </div>
                <div className="metric-grid">
                  <div className="metric-card metric-danger">
                    <span>Criticality</span>
                    <strong>{analysis.critical_path_explanation?.criticality_score ?? 'N/A'}</strong>
                  </div>
                  <div className="metric-card">
                    <span>Path nodes</span>
                    <strong>{analysis.critical_path.length}</strong>
                  </div>
                  <div className="metric-card metric-warn">
                    <span>Missing detection</span>
                    <strong>{analysis.critical_path_explanation?.missing_detection_nodes.length ?? 0}</strong>
                  </div>
                  <div className="metric-card">
                    <span>Trust crossings</span>
                    <strong>{analysis.critical_path_explanation?.trust_boundary_nodes.length ?? 0}</strong>
                  </div>
                </div>
                {analysis.most_likely_path ? (
                  <div className="metric-grid">
                    <div className="metric-card metric-good">
                      <span>Most likely path</span>
                      <strong>{(analysis.most_likely_path.probability * 100).toFixed(1)}%</strong>
                      <small>{analysis.most_likely_path.assumption}</small>
                    </div>
                    <div className="metric-card metric-warn">
                      <span>Probabilistic risk</span>
                      <strong>{analysis.most_likely_path.risk_score}</strong>
                      <small>Impact {analysis.most_likely_path.impact_score}</small>
                    </div>
                  </div>
                ) : null}
                <div className="explain-list">
                  {(analysis.critical_path_explanation?.reasons ?? []).map((reason) => (
                    <div key={reason}>{reason}</div>
                  ))}
                </div>
                {analysis.missing_detection_details?.length ? (
                  <div className="data-list">
                    {analysis.missing_detection_details.map((detail) => (
                      <div className="data-row" key={detail.node_id}>
                        <div>
                          <strong>{detail.technique} | {detail.action_type}</strong>
                          <small>{detail.node_id} | target {detail.target}</small>
                        </div>
                        <StatusBadge tone="warn">Missing detection</StatusBadge>
                      </div>
                    ))}
                  </div>
                ) : null}
                <div className="trust-zones" aria-label="Trust boundary visualization">
                  {trustZones.map((zone) => (
                    <div className="trust-zone" key={zone.zone}>
                      <h3>{zone.zone}</h3>
                      <div>
                        {zone.nodes.length ? zone.nodes.map((node) => (
                          <span key={node?.step_id}>{node?.action_type || node?.technique}</span>
                        )) : <span>No step</span>}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </Panel>
          ) : null}

          <Panel title="Asset-aware risk" description="Highlights attack steps that target high-criticality or crown-jewel assets when CIR metadata supplies those signals.">
            {topAssetRisks.length ? (
                <div className="data-list">
                  {topAssetRisks.map((signal) => (
                    <div className="data-row" key={signal.node_id}>
                      <div>
                        <strong>{signal.asset}</strong>
                        <small>
                          {signal.node_id} | asset criticality {signal.asset_criticality} | crown jewel {signal.crown_jewel_exposure}
                        </small>
                      </div>
                      <StatusBadge tone={signal.risk_score >= 80 ? 'danger' : signal.risk_score >= 60 ? 'warn' : 'info'}>
                        Risk {signal.risk_score}
                      </StatusBadge>
                    </div>
                  ))}
                </div>
            ) : (
              <EmptyState title="No high-value asset metadata yet" description="Add crown_jewel_exposure, trust_boundary_crossings, or high-criticality asset targets to make this analysis business-aware." />
            )}
          </Panel>

          {timeline && (
            <Panel title="Attack graph time machine" description="Replay the ordered attack steps derived from the active CIR.">
              <AttackTimelinePlayer timeline={timeline} />
            </Panel>
          )}

          {analysis?.critical_path.length ? (
            <Panel title="Critical path metrics" description="The backend returns the longest ordered attack chain; risk weighting is shown when supplied by analysis.">
              <div className="metric-grid">
                <div className="metric-card">
                  <span>High-risk nodes</span>
                  <strong>{analysis.critical_path.filter((id) => highRiskIds.has(id)).length}</strong>
                </div>
                <div className="metric-card">
                  <span>Graph coverage</span>
                  <strong>{analysis.coverage_percentage}%</strong>
                </div>
                <div className="metric-card">
                  <span>Kill-chain completion</span>
                  <strong>{analysis.kill_chain_completion}%</strong>
                </div>
                <div className="metric-card">
                  <span>Attack maturity</span>
                  <strong>{analysis.attack_maturity}</strong>
                </div>
              </div>
            </Panel>
          ) : null}
        </>
      ) : (
        <EmptyState title="No attack graph available" description="Analyze a threat narrative first to populate the graph workspace." />
      )}
    </div>
  );
}
