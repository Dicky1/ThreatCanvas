import React, { useEffect, useState } from 'react';
import { api } from '../api/client';

// 1. Definisikan interface props di sini
interface CoverageProps {
  scenarioId: string;
}

// 2. Gunakan interface pada komponen
const Coverage: React.FC<CoverageProps> = ({ scenarioId }) => {
  const [report, setReport] = useState<any>(null);
  const [loading, setLoading] = useState<boolean>(true);

  useEffect(() => {
    const fetchCoverage = async () => {
      try {
        setLoading(true);
        const data = await api.coverage(scenarioId);
        setReport(data);
      } catch (error) {
        console.error("Error fetching coverage:", error);
      } finally {
        setLoading(false);
      }
    };

    if (scenarioId) fetchCoverage();
  }, [scenarioId]);

  if (loading) return <div className="text-gray-400 p-4">Analyzing scenario metrics...</div>;
  if (!report) return <div className="text-red-400 p-4">No report available.</div>;

  return (
    <div className="space-y-6 p-4">
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        {[
          { label: 'Overall Score', val: `${report.overall_score}%` },
          { label: 'Threat Completeness', val: `${report.threat_completeness}%` },
          { label: 'Graph Integrity', val: report.graph_integrity.toFixed(2) },
          { label: 'Nodes/Edges', val: `${report.total_nodes} / ${report.total_edges}` }
        ].map((m, i) => (
          <div key={i} className="bg-gray-900 p-4 rounded-lg border border-gray-800">
            <p className="text-xs text-gray-500 uppercase">{m.label}</p>
            <p className="text-lg font-bold text-primary">{m.val}</p>
          </div>
        ))}
      </div>

      <div className="bg-gray-900 p-6 rounded-lg border border-gray-800">
        <h4 className="text-white font-semibold mb-2">Missing Tactics</h4>
        <p className="text-sm text-red-400">{report.missing_tactics.join(", ") || "None - All tactics covered!"}</p>
        
        <h4 className="text-white font-semibold mt-4 mb-2">Strategic Recommendations</h4>
        <ul className="list-disc list-inside space-y-1">
          {report.recommendations.map((r: string, i: number) => <li key={i} className="text-sm text-gray-300">{r}</li>)}
        </ul>
      </div>
    </div>
  );
};

export default Coverage;