import { useEffect, useState } from 'react';
import { ReactFlow, Controls, Background } from 'reactflow';
import 'reactflow/dist/style.css';
import { api } from '../api/client';
import type { CIRSpecification } from '../types/api';

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

const RELATIONSHIPS = ['ALL', 'USES', 'TARGETS', 'REQUIRES', 'EXPLOITS', 'PRODUCES', 'DETECTED_BY', 'COUNTERED_BY', 'CONNECTED_TO'];

export default function ThreatGraph({ data, specification, scenarioId }: { data: any; specification?: CIRSpecification; scenarioId?: string }) {
  const [analysis, setAnalysis] = useState<GraphAnalysis | null>(null);
  const [selectedNode, setSelectedNode] = useState<any>(null);
  const [query, setQuery] = useState('');
  const [relationship, setRelationship] = useState('ALL');
  const [knowledgeMode, setKnowledgeMode] = useState(false);
  const [fullscreen, setFullscreen] = useState(false);

  useEffect(() => {
    if (!scenarioId) return;
    api.analysis(scenarioId).then(setAnalysis).catch(console.error);
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

  const graph = (() => {
    const search = query.trim().toLowerCase();
    if (knowledgeMode && specification?.entities?.length) {
      const entities = specification.entities.filter((entity) => !search || `${entity.id} ${entity.name ?? ''} ${entity.entity_type}`.toLowerCase().includes(search));
      const ids = new Set(entities.map((entity) => entity.id));
      const relationships = (specification.relationships ?? []).filter((edge) => (relationship === 'ALL' || edge.relationship === relationship) && ids.has(edge.source) && ids.has(edge.target));
      return {
        nodes: entities.map((entity, index) => ({ id: entity.id, data: { label: entity.name || entity.entity_type }, position: { x: (index % 4) * 240, y: Math.floor(index / 4) * 150 }, style: { background: '#172b38', color: '#dff3fb', border: '1px solid #5894b1' } })),
        edges: relationships.map((edge) => ({ id: edge.stix_id || `r-${edge.source}-${edge.target}`, source: edge.source, target: edge.target, label: edge.relationship, animated: true })),
        lookup: new Map(entities.map((entity) => [entity.id, entity])),
      };
    }
    const visible = data.nodes.filter((node: any) => !search || `${node.step_id} ${node.action_type} ${node.technique} ${node.tactic} ${node.target}`.toLowerCase().includes(search));
    const ids = new Set(visible.map((node: any) => node.step_id));
    return {
      nodes: visible.map((node: any, index: number) => ({ id: node.step_id, data: { label: node.action_type }, position: { x: (index % 4) * 240, y: Math.floor(index / 4) * 150 }, style: getNodeStyle(node.step_id, node.action_type) })),
      edges: (data.edges || []).filter((edge: any) => (relationship === 'ALL' || edge.relationship === relationship) && ids.has(edge.from) && ids.has(edge.to)).map((edge: any) => ({ id: `e${edge.from}-${edge.to}`, source: edge.from, target: edge.to, label: edge.relationship, animated: true })),
      lookup: new Map(visible.map((node: any) => [node.step_id, node])),
    };
  })();

  return (
    <div className={`${fullscreen ? 'fixed inset-4 z-40 bg-[#0b1016] p-4 shadow-2xl' : ''} flex min-h-[700px] flex-col gap-4`}>
      <div className="flex flex-wrap items-center justify-between gap-2 rounded-lg border border-gray-800 bg-surface px-3 py-2 text-xs">
        <div className="flex flex-wrap items-center gap-2">
          <label className="flex items-center gap-2 text-gray-400"><span className="sr-only">Search graph</span><input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search nodes or entities" className="w-48 rounded border border-gray-700 bg-background px-2.5 py-1.5 text-gray-200 outline-none focus:border-primary" /></label>
          <select aria-label="Relationship filter" value={relationship} onChange={(event) => setRelationship(event.target.value)} className="rounded border border-gray-700 bg-background px-2.5 py-1.5 text-gray-300"><option value="ALL">All relationships</option>{RELATIONSHIPS.slice(1).map((item) => <option key={item} value={item}>{item}</option>)}</select>
          {specification?.entities?.length ? <button className="rounded border border-gray-700 px-2.5 py-1.5 text-gray-300 hover:border-primary" onClick={() => setKnowledgeMode((value) => !value)}>{knowledgeMode ? 'Attack Graph' : 'Knowledge Graph'}</button> : null}
        </div>
        <button aria-label={fullscreen ? 'Exit fullscreen graph' : 'Open fullscreen graph'} className="rounded border border-gray-700 px-2.5 py-1.5 text-gray-400 hover:border-primary hover:text-white" onClick={() => setFullscreen((value) => !value)}>{fullscreen ? 'Exit fullscreen' : 'Fullscreen'}</button>
      </div>
      <div className="flex min-h-[460px] flex-1 flex-col gap-4 xl:flex-row">
        <div className="min-h-[420px] min-w-0 flex-1 border border-gray-800 rounded-lg bg-surface">
          <ReactFlow nodes={graph.nodes} edges={graph.edges} onNodeClick={(_, n) => setSelectedNode(graph.lookup.get(n.id))} fitView>
            <Background /><Controls />
          </ReactFlow>
        </div>
        
        {analysis && (
          <div className="max-h-[320px] w-full shrink-0 overflow-y-auto border border-gray-800 rounded-lg bg-surface p-4 text-gray-300 text-[11px] xl:max-h-none xl:w-[300px]">
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

      <div className="min-h-[220px] border border-gray-800 rounded-lg bg-surface p-4 overflow-y-auto text-sm text-gray-300">
        <h3 className="font-bold text-white mb-2">CIR Inspector</h3>
        {selectedNode ? (
          <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
            <p><strong>Action:</strong> {selectedNode.action_type}</p>
            <p><strong>Tactic:</strong> {selectedNode.tactic}</p>
            <p><strong>Target:</strong> {selectedNode.target}</p>
            {selectedNode.confidence !== undefined && <p><strong>Confidence:</strong> {Math.round(Number(selectedNode.confidence) * 100)}%</p>}
            {selectedNode.provenance && <p><strong>Provenance:</strong> {selectedNode.provenance.source || selectedNode.provenance.type || "Recorded"}</p>}
            {(selectedNode.created_at || selectedNode.updated_at) && <p><strong>Timestamp:</strong> {selectedNode.updated_at || selectedNode.created_at}</p>}
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
