export default function RichCIRInspector({ nodeData }: { nodeData: any }) {
  if (!nodeData) {
    return (
      <div className="h-full flex items-center justify-center text-gray-500 border border-gray-800 rounded-lg bg-surface p-4">
        Select a node to inspect its CIR details.
      </div>
    );
  }

  return (
    <div className="h-full overflow-y-auto border border-gray-800 rounded-lg bg-surface p-4 text-sm text-gray-300">
      <h3 className="font-bold text-lg text-white mb-4 border-b border-gray-700 pb-2">Node Inspector</h3>
      <div className="space-y-3">
        <p><strong>Step ID:</strong> {nodeData.step_id}</p>
        <p><strong>Tactic:</strong> {nodeData.tactic}</p>
        <p><strong>Technique:</strong> {nodeData.technique}</p>
        <p><strong>Target:</strong> {nodeData.target}</p>
        <p><strong>Action Type:</strong> {nodeData.action_type}</p>
        
        <div className="mt-4">
          <strong className="block mb-2 text-white">Evidence:</strong>
          {nodeData.evidence?.length > 0 ? nodeData.evidence.map((ev: any, idx: number) => (
            <div key={idx} className="bg-background p-2 rounded border border-gray-700 mb-2 text-xs">
              <p>Type: {ev.type}</p>
              {ev.description && <p className="text-gray-400 italic">"{ev.description}"</p>}
              {ev.command_line && <p>Cmd: {ev.command_line}</p>}
              {ev.ip && <p>IP: {ev.ip}</p>}
              {ev.hash_sha256 && <p className="truncate">Hash: {ev.hash_sha256}</p>}
            </div>
          )) : <p className="text-gray-500 italic">No evidence available.</p>}
        </div>
      </div>
    </div>
  );
}