import { ReactFlow, Controls, Background } from 'reactflow';
import 'reactflow/dist/style.css';

import type { CIRGraph } from '../store/useThreatStore';

export default function ThreatGraph({ data }: { data: CIRGraph }) {
  // Mengubah node CIR menjadi node ReactFlow
  const nodes = data.nodes.map((node, index) => ({
    id: node.step_id,
    data: { label: `${node.tactic}: ${node.action_type}` },
    position: { x: index * 200, y: 100 },
    style: { background: '#171717', color: '#3b82f6', border: '1px solid #3b82f6' },
  }));

  const edges = data.edges.map((edge) => ({
    id: `e${edge.from}-${edge.to}`,
    source: edge.from,
    target: edge.to,
    animated: true,
  }));

  return (
    <div className="h-[400px] w-full border border-gray-800 rounded-lg bg-surface">
      <ReactFlow nodes={nodes} edges={edges} fitView>
        <Background />
        <Controls />
      </ReactFlow>
    </div>
  );
}