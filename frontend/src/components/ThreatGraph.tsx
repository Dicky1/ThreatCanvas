import React, { useEffect, useState } from 'react';
import { ReactFlow, Controls, Background } from 'reactflow';
import 'reactflow/dist/style.css';

interface GraphAnalysis {
  node_count: number;
  edge_count: number;
  critical_path: string[];
  detection_choke_points: string[];
  high_risk_nodes: { node_id: string }[];
  entry_points: string[];
  exit_points: string[];
  attack_maturity: string;
  attack_complexity: number;
  kill_chain_completion: number;
  blast_radius: any[];
  longest_chain: number;
  shortest_chain: number;
  graph_density: number;
  connected_components: number;
  average_degree: number;
}

export default function ThreatGraph({ data, scenarioId }: { data: any; scenarioId?: string }) {
  const [analysis, setAnalysis] = useState<GraphAnalysis | null>(null);
  const [selectedNode, setSelectedNode] = useState<any>(null);

  useEffect(() => {
    if (!scenarioId) return;
    fetch(`/api/v1/graph-analysis/${scenarioId}`)
      .then(res => res.ok ? res.json() : null)
      .then(data => setAnalysis(data))
      .catch(console.error);
  }, [scenarioId]);

  if (!data?.nodes) return <div className="p-4 text-gray-500">Generating graph workspace...</div>;

  // LOGIKA WARNA DENGAN DETEKSI HIGH-RISK DINAMIS
  const getNodeStyle = (id: string, actionType: string = '') => {
    if (!analysis) return { background: '#171717', color: '#3b82f6', border: '1px solid #3b82f6' };
    
    // 1. Prioritas Utama: Entry Point (Hijau)
    if (analysis.entry_points?.includes(id)) {
      return { background: '#16A34A', color: '#fff', border: '2px solid #15803D' };
    }
    
    // 2. Prioritas Kedua: Exit Point (Merah)
    if (analysis.exit_points?.includes(id)) {
      return { background: '#DC2626', color: '#fff', border: '2px solid #B91C1C' };
    }
    
    // 3. Prioritas Ketiga: High Risk Node (Orange - Otomatis mendeteksi backend & keyword aksi berbahaya)
    const isHighRiskBackend = analysis.high_risk_nodes?.some((n: any) => n.node_id === id);
    const actionLower = actionType.toLowerCase();
    const isHighRiskKeyword = actionLower.includes('credential') || actionLower.includes('dump') || actionLower.includes('ransomware') || actionLower.includes('privilege');
    
    if (isHighRiskBackend || isHighRiskKeyword) {
      return { background: '#EA580C', color: '#fff', border: '2px solid #C2410C' };
    }
    
    // 4. Prioritas Keempat: Detection Choke Point (Ungu)
    if (analysis.detection_choke_points?.includes(id)) {
      return { background: '#9333EA', color: '#fff', border: '2px solid #7E22CE' };
    }
    
    // 5. Terakhir: Critical Path (Kuning)
    if (analysis.critical_path?.includes(id)) {
      return { background: '#EAB308', color: '#000', border: '2px solid #CA8A04' };
    }

    return { background: '#171717', color: '#3b82f6', border: '1px solid #3b82f6' };
  };

  const nodes = data.nodes.map((n: any, i: number) => ({
    id: n.step_id, 
    data: { label: n.action_type }, 
    position: { x: i * 200, y: 100 }, 
    style: getNodeStyle(n.step_id, n.action_type),
  }));

  const edges = (data.edges || []).map((e: any) => ({ id: `e${e.from}-${e.to}`, source: e.from, target: e.to, animated: true }));

  return (
    <div className="flex flex-col h-[700px] gap-4">
      <div className="flex flex-row h-[60%] gap-4">
        <div className="flex-grow border border-gray-800 rounded-lg bg-surface">
          <ReactFlow nodes={nodes} edges={edges} onNodeClick={(_, n) => setSelectedNode(data.nodes.find((x: any) => x.step_id === n.id))} fitView>
            <Background /><Controls />
          </ReactFlow>
        </div>
        
        {analysis && (
          <div className="w-[300px] border border-gray-800 rounded-lg bg-surface p-4 text-gray-300 text-[11px] overflow-y-auto">
            <h3 className="font-bold text-white mb-3 uppercase tracking-wider border-b border-gray-700 pb-2">Analysis Dashboard</h3>
            <div className="grid grid-cols-2 gap-y-2 gap-x-2">
              <p>Nodes: <span className="text-white">{analysis.node_count}</span></p>
              <p>Edges: <span className="text-white">{analysis.edge_count}</span></p>
              <p>Critical Path: <span className="text-white">{analysis.critical_path?.length || 0}</span></p>
              <p>Density: <span className="text-white">{analysis.graph_density?.toFixed(2)}</span></p>
              <p>Components: <span className="text-white">{analysis.connected_components}</span></p>
              <p>Avg Degree: <span className="text-white">{analysis.average_degree?.toFixed(1)}</span></p>
              <p>Longest Chn: <span className="text-white">{analysis.longest_chain}</span></p>
              <p>Shortest Chn: <span className="text-white">{analysis.shortest_chain}</span></p>
              <p>Complexity: <span className="text-white">{analysis.attack_complexity}</span></p>
              <p>Maturity: <span className="text-white">{analysis.attack_maturity}</span></p>
            </div>
            
            <div className="mt-4 pt-4 border-t border-gray-700">
              <p className="font-semibold text-white mb-2">Kill Chain Coverage: {analysis.kill_chain_completion}%</p>
              <div className="w-full bg-gray-700 h-2 rounded-full"><div className="bg-blue-500 h-2 rounded-full" style={{ width: `${analysis.kill_chain_completion}%` }}></div></div>
            </div>

            <div className="mt-4 pt-4 border-t border-gray-700">
              <h4 className="font-bold text-white mb-2 uppercase tracking-wider">Legend</h4>
              <div className="space-y-2">
                <div className="flex items-center"><span className="w-3 h-3 rounded-full bg-[#16A34A] mr-2"></span> Entry Point</div>
                <div className="flex items-center"><span className="w-3 h-3 rounded-full bg-[#DC2626] mr-2"></span> Exit Point</div>
                <div className="flex items-center"><span className="w-3 h-3 rounded-full bg-[#EAB308] mr-2"></span> Critical Path</div>
                <div className="flex items-center"><span className="w-3 h-3 rounded-full bg-[#EA580C] mr-2"></span> High Risk</div>
                <div className="flex items-center"><span className="w-3 h-3 rounded-full bg-[#9333EA] mr-2"></span> Choke Point</div>
              </div>
            </div>
          </div>
        )}
      </div>

      <div className="h-[40%] border border-gray-800 rounded-lg bg-surface p-4 overflow-y-auto text-sm text-gray-300">
        <h3 className="font-bold text-white mb-2">CIR Inspector</h3>
        {selectedNode ? (
          <div className="grid grid-cols-2 gap-4">
            <p><strong>Action:</strong> {selectedNode.action_type}</p>
            <p><strong>Tactic:</strong> {selectedNode.tactic}</p>
            <p><strong>Target:</strong> {selectedNode.target}</p>
            {analysis?.blast_radius?.find((b: any) => b.node_id === selectedNode.step_id) && (
              <p className="text-orange-400"><strong>Blast Radius:</strong> {analysis.blast_radius.find((b: any) => b.node_id === selectedNode.step_id).impacted_count} nodes</p>
            )}
            <div className="col-span-2 bg-background p-3 rounded border border-gray-700">
              <strong className="text-white">Evidence:</strong>
              <p className="mt-1">{selectedNode.evidence?.[0]?.description || "No description provided."}</p>
            </div>
          </div>
        ) : <p className="text-gray-500 italic">Select a node to inspect its attributes.</p>}
      </div>
    </div>
  );
}