import React, { useEffect, useState } from 'react';

interface RiskNode { 
  node_id: string; 
  technique_id: string; 
  tactic: string; 
  risk_level: string; 
}

interface DetectionGap { 
  technique_id: string; 
  technique_name: string; 
  status: string; 
}

interface RankedPriority { 
  technique_id: string; 
  technique_name: string; 
  risk_level: string; 
}

interface ThreatReasoning {
  severity: string;
  severity_score: number;
  confidence: string;
  attack_objective: string;
  attack_complexity: string;
  kill_chain_completion: string;
  highest_risk_nodes: RiskNode[];
  priority_ranking: RankedPriority[];
  detection_gaps: DetectionGap[];
  recommended_actions: string[];
  recommended_controls: string[];
  executive_summary: string;
}

const ThreatAssessment: React.FC<{ scenarioId: string }> = ({ scenarioId }) => {
  const [data, setData] = useState<ThreatReasoning | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!scenarioId) return;
    const fetchReasoning = async () => {
      setLoading(true);
      try {
        const response = await fetch(`http://localhost:8000/api/v1/reasoning/${scenarioId}`);
        if (!response.ok) throw new Error('Gagal mengambil data Threat Reasoning');
        setData(await response.json());
      } catch (err: any) {
        setError(err.message);
      } finally {
        setLoading(false);
      }
    };
    fetchReasoning();
  }, [scenarioId]);

  if (loading) return <div className="p-6 text-center text-gray-400">Menganalisis Threat Reasoning...</div>;
  if (error) return <div className="p-6 text-center text-red-500">Error: {error}</div>;
  if (!data) return null;

  // Pewarnaan Dinamis Severity
  const severityColor = 
    data.severity === 'Critical' ? 'bg-red-50 text-red-800 border-red-500' :
    data.severity === 'High' ? 'bg-orange-50 text-orange-800 border-orange-500' :
    data.severity === 'Medium' ? 'bg-yellow-50 text-yellow-800 border-yellow-500' :
    'bg-green-50 text-green-800 border-green-500';

  return (
    <div className="flex flex-col gap-6 text-gray-100">
      
      {/* 1. Top Metrics */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className={`p-5 rounded-lg border-l-4 shadow-sm ${severityColor}`}>
          <h3 className="text-xs font-semibold uppercase tracking-wider opacity-70">Threat Severity</h3>
          <div className="mt-1 text-3xl font-bold">{data.severity}</div>
          <div className="text-sm mt-1 opacity-80 font-medium">Score: {data.severity_score}</div>
        </div>
        
        <div className="p-5 bg-surface border border-gray-700 rounded-lg shadow-sm">
          <h3 className="text-xs font-semibold text-gray-400 uppercase tracking-wider">Attack Objective</h3>
          <div className="mt-1 text-xl font-bold text-white">{data.attack_objective}</div>
          <div className="text-sm mt-1 text-gray-400">Complexity: {data.attack_complexity}</div>
        </div>

        <div className="p-5 bg-surface border border-gray-700 rounded-lg shadow-sm">
          <h3 className="text-xs font-semibold text-gray-400 uppercase tracking-wider">Kill Chain Progress</h3>
          <div className="mt-1 text-2xl font-bold text-white">{data.kill_chain_completion}</div>
        </div>

        <div className="p-5 bg-surface border border-gray-700 rounded-lg shadow-sm">
          <h3 className="text-xs font-semibold text-gray-400 uppercase tracking-wider">AI Confidence</h3>
          <div className="mt-1 text-xl font-bold text-blue-400">{data.confidence}</div>
        </div>
      </div>

      {/* 2. Executive Summary */}
      <div className="p-5 bg-blue-950/30 border border-blue-900 rounded-lg shadow-sm">
        <h2 className="text-sm font-bold text-blue-300 uppercase tracking-wider mb-2">Executive Summary</h2>
        <p className="text-gray-300 leading-relaxed text-md">{data.executive_summary}</p>
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-2 gap-6">
        
        {/* 3. Detection Gaps */}
        <div className="p-5 bg-surface border border-gray-700 rounded-lg shadow-sm">
          <h3 className="text-md font-bold text-white mb-4 border-b border-gray-700 pb-2">Detection Gaps</h3>
          {data.detection_gaps.length > 0 ? (
            <div className="flex flex-col gap-4">
              {data.detection_gaps.map((gap, i) => (
                <div key={i} className="flex flex-col border-b border-gray-800 pb-3 last:border-0 last:pb-0">
                  <span className="font-mono text-sm font-bold text-gray-200">{gap.technique_id}</span>
                  <span className="text-sm text-gray-400 mb-2">{gap.technique_name}</span>
                  <div className="flex items-center gap-2">
                    {gap.status === 'Not Covered' ? '🔴' : gap.status === 'Partially Covered' ? '🟡' : '🟢'}
                    <span className="text-sm font-semibold text-gray-300">{gap.status}</span>
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <p className="text-sm text-gray-500">No detection gaps identified.</p>
          )}
        </div>

        {/* 4. Priority Ranking */}
        <div className="p-5 bg-surface border border-gray-700 rounded-lg shadow-sm">
          <h3 className="text-md font-bold text-white mb-4 border-b border-gray-700 pb-2">Priority Ranking</h3>
          {data.priority_ranking.length > 0 ? (
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="border-b border-gray-700 text-gray-400 text-sm">
                  <th className="pb-2 font-medium w-16">Priority</th>
                  <th className="pb-2 font-medium">Technique</th>
                  <th className="pb-2 font-medium">Risk</th>
                </tr>
              </thead>
              <tbody>
                {data.priority_ranking.map((item, i) => (
                  <tr key={i} className="border-b border-gray-800 last:border-0">
                    <td className="py-3 text-gray-400 font-mono text-sm">{i + 1}</td>
                    <td className="py-3">
                      <div className="font-mono font-bold text-gray-200 text-sm">{item.technique_id}</div>
                      <div className="text-xs text-gray-400 mt-1">{item.technique_name}</div>
                    </td>
                    <td className="py-3 font-semibold text-sm whitespace-nowrap">
                      {item.risk_level === 'Critical' ? '🔴 Critical' : 
                       item.risk_level === 'High' ? '🟠 High' : 
                       item.risk_level === 'Medium' ? '🟡 Medium' : '🟢 Low'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : (
            <p className="text-sm text-gray-500">No high priority techniques identified.</p>
          )}
        </div>

        {/* 5. Recommended Controls */}
        <div className="p-5 bg-surface border border-gray-700 rounded-lg shadow-sm">
          <h3 className="text-md font-bold text-white mb-4 border-b border-gray-700 pb-2">Recommended Controls</h3>
          <ul className="list-disc list-inside space-y-2 text-gray-300 text-sm">
            {data.recommended_controls.length > 0 ? (
              data.recommended_controls.map((control, i) => <li key={i}>{control}</li>)
            ) : (
              <li className="text-gray-500 list-none">No specific controls recommended.</li>
            )}
          </ul>
        </div>

        {/* 6. Recommended Actions */}
        <div className="p-5 bg-surface border border-gray-700 rounded-lg shadow-sm">
          <h3 className="text-md font-bold text-white mb-4 border-b border-gray-700 pb-2">Recommended Actions</h3>
          <ul className="list-disc list-inside space-y-2 text-gray-300 text-sm">
            {data.recommended_actions.length > 0 ? (
              data.recommended_actions.map((action, i) => <li key={i}>{action}</li>)
            ) : (
              <li className="text-gray-500 list-none">No specific actions recommended.</li>
            )}
          </ul>
        </div>

      </div>
    </div>
  );
};

export default ThreatAssessment;