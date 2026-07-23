import React, { useState } from 'react';
import { 
  ShieldAlert, ShieldCheck, AlertTriangle, Activity, 
  ArrowDown, ArrowUp, Minus, CheckCircle, XCircle, Info, Layers, Cpu 
} from 'lucide-react';

interface RemovedNode {
  step_id: string;
  technique: string;
  tactic: string;
  reason: string;
}

interface SimulationMetrics {
  severity: string;
  risk_score: number;
  kill_chain_completion: string;
  blast_radius: number;
  complexity: string;
  critical_path: string[];
  maturity_level: string;
  node_count: number;
  edge_count: number;
  graph_density: number;
  connected_components: number;
  average_degree: number;
}

interface SimulationComparison {
  severity_change: string;
  risk_score_reduction: number;
  kill_chain_reduction: string;
  blast_radius_reduction: number;
  complexity_change: string;
  node_reduction: number;
  edge_reduction: number;
  apds_change: string;
  critical_path_reduction: number;
  graph_density_change: number;
}

interface SimulationResult {
  blocked_techniques: string[];
  removed_nodes: RemovedNode[];
  removed_edges: any[];
  remaining_nodes: string[];
  metrics_before: SimulationMetrics;
  metrics_after: SimulationMetrics;
  comparison: SimulationComparison;
  risk_reduction: number;
  attack_path_disruption_score: number;
  optimized_controls: string[];
  simulation_summary: string;
  warning?: string;
}

interface AttackSimulationViewProps {
  scenarioId: string;
}

export default function AttackSimulationView({ scenarioId }: AttackSimulationViewProps) {
  const [blockedInput, setBlockedInput] = useState<string>("T1059.001, T1003.001");
  const [simulationData, setSimulationData] = useState<SimulationResult | null>(null);
  const [loading, setLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const [activeTabPanel, setActiveTabPanel] = useState<"metrics" | "table" | "controls">("metrics");
  
  // State untuk interaktif node modal/tooltip (Poin 4)
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null);

  const runSimulation = async () => {
    setLoading(true);
    setError(null);
    try {
      const techniques = blockedInput.split(',').map(t => t.trim()).filter(Boolean);
      
      const response = await fetch(`http://localhost:8000/api/v1/${scenarioId}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ blocked_techniques: techniques })
      });

      if (!response.ok) throw new Error("Gagal menjalankan simulasi dari backend.");
      const data: SimulationResult = await response.json();
      setSimulationData(data);
      if (data.remaining_nodes.length > 0) {
        setSelectedNodeId(data.remaining_nodes[0]);
      }
    } catch (err: any) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  // Helper untuk Status Attack Chain
  const getChainStatusBadge = (apds: number) => {
    if (apds >= 80) return { label: "ATTACK CHAIN BROKEN", color: "bg-emerald-950 text-emerald-400 border-emerald-800", icon: <CheckCircle size={16} /> };
    if (apds > 0) return { label: "ATTACK CHAIN DEGRADED", color: "bg-amber-950 text-amber-400 border-amber-800", icon: <AlertTriangle size={16} /> };
    return { label: "STILL VIABLE", color: "bg-rose-950 text-rose-400 border-rose-800", icon: <XCircle size={16} /> };
  };

  // Helper untuk Label APDS Komunikatif (Poin 2)
  const getApdsLabel = (score: number) => {
    if (score >= 80) return { text: "Critical Disruption", color: "text-emerald-400" };
    if (score >= 50) return { text: "Moderate Disruption", color: "text-cyan-400" };
    if (score > 0) return { text: "Low Disruption", color: "text-amber-400" };
    return { text: "No Disruption", color: "text-slate-500" };
  };

  return (
    <div className="space-y-6 text-slate-100">
      {/* Header Panel */}
      <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-4 bg-slate-900 p-6 rounded-xl border border-slate-800 shadow-xl">
        <div>
          <h1 className="text-xl font-bold flex items-center gap-2">
            <Activity className="text-cyan-400" /> Attack Simulation & Defense Optimization
          </h1>
          <p className="text-slate-400 text-xs mt-1">Simulasikan pemblokiran teknik mitigasi dan analisis dampaknya pada attack graph secara deterministik.</p>
        </div>
        <div className="flex items-center gap-3 w-full md:w-auto">
          <input 
            type="text" 
            value={blockedInput}
            onChange={(e) => setBlockedInput(e.target.value)}
            placeholder="T1059.001, T1003.001"
            className="bg-slate-950 border border-slate-700 px-4 py-2 rounded-lg text-xs focus:outline-none focus:border-cyan-500 flex-1 md:w-64 font-mono"
          />
          <button 
            onClick={runSimulation}
            disabled={loading}
            className="bg-cyan-600 hover:bg-cyan-500 px-5 py-2 rounded-lg text-xs font-semibold transition disabled:opacity-50 cursor-pointer shadow-lg shadow-cyan-950"
          >
            {loading ? "Simulating..." : "Run Simulation"}
          </button>
        </div>
      </div>

      {error && (
        <div className="bg-red-950/50 border border-red-800 text-red-200 p-4 rounded-xl flex items-center gap-3 text-xs">
          <AlertTriangle className="text-red-400 shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {simulationData && (
        <div className="space-y-6">
          {simulationData.warning && (
            <div className="bg-amber-950/40 border border-amber-800/60 text-amber-200 p-4 rounded-xl flex items-center gap-3 text-xs">
              <AlertTriangle className="text-amber-400 shrink-0" />
              <span>{simulationData.warning}</span>
            </div>
          )}

          {/* Top Status & APDS Progress Bar dengan Label Komunikatif (Poin 2) */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className="bg-slate-900 border border-slate-800 p-5 rounded-xl flex flex-col justify-between">
              <span className="text-[11px] font-medium text-slate-400 uppercase tracking-wider">Attack Chain Status</span>
              <div className="mt-3 flex items-center gap-2">
                {(() => {
                  const badge = getChainStatusBadge(simulationData.attack_path_disruption_score);
                  return (
                    <div className={`px-3 py-1.5 rounded-lg border text-xs font-bold flex items-center gap-2 ${badge.color}`}>
                      {badge.icon} {badge.label}
                    </div>
                  );
                })()}
              </div>
            </div>

            <div className="md:col-span-2 bg-slate-900 border border-slate-800 p-5 rounded-xl flex flex-col justify-between">
              <div className="flex justify-between items-center">
                <span className="text-[11px] font-medium text-slate-400 uppercase tracking-wider">Attack Path Disruption Score (APDS)</span>
                <div className="flex items-center gap-2">
                  <span className={`text-xs font-bold px-2 py-0.5 rounded bg-slate-950 border border-slate-800 ${getApdsLabel(simulationData.attack_path_disruption_score).color}`}>
                    {getApdsLabel(simulationData.attack_path_disruption_score).text}
                  </span>
                  <span className="text-lg font-bold text-cyan-400 font-mono">{simulationData.attack_path_disruption_score}%</span>
                </div>
              </div>
              <div className="w-full bg-slate-950 rounded-full h-3 mt-3 border border-slate-800 overflow-hidden">
                <div 
                  className="bg-gradient-to-r from-cyan-600 to-emerald-500 h-full rounded-full transition-all duration-500" 
                  style={{ width: `${simulationData.attack_path_disruption_score}%` }}
                ></div>
              </div>
            </div>
          </div>

          {/* Before vs After Metric Cards */}
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
            <MetricCard 
              title="Risk Score" 
              before={simulationData.metrics_before.risk_score} 
              after={simulationData.metrics_after.risk_score} 
              reduction={simulationData.comparison.risk_score_reduction}
            />
            <MetricCard 
              title="Severity" 
              before={simulationData.metrics_before.severity} 
              after={simulationData.metrics_after.severity} 
              isText
            />
            <MetricCard 
              title="Critical Path" 
              before={`${simulationData.metrics_before.critical_path.length} nodes`} 
              after={`${simulationData.metrics_after.critical_path.length} nodes`} 
              reduction={simulationData.comparison.critical_path_reduction}
            />
            <MetricCard 
              title="Blast Radius" 
              before={simulationData.metrics_before.blast_radius} 
              after={simulationData.metrics_after.blast_radius} 
              reduction={simulationData.comparison.blast_radius_reduction}
            />
          </div>

          {/* Sub Navigation untuk Detail View */}
          <div className="flex gap-4 border-b border-slate-800 pb-2">
            <button 
              onClick={() => setActiveTabPanel("metrics")}
              className={`text-xs font-semibold pb-2 border-b-2 transition ${activeTabPanel === "metrics" ? "border-cyan-500 text-cyan-400" : "border-transparent text-slate-400"}`}
            >
              Summary & Graph Nodes
            </button>
            <button 
              onClick={() => setActiveTabPanel("table")}
              className={`text-xs font-semibold pb-2 border-b-2 transition ${activeTabPanel === "table" ? "border-cyan-500 text-cyan-400" : "border-transparent text-slate-400"}`}
            >
              Comparison Table (Δ Metrics)
            </button>
            <button 
              onClick={() => setActiveTabPanel("controls")}
              className={`text-xs font-semibold pb-2 border-b-2 transition ${activeTabPanel === "controls" ? "border-cyan-500 text-cyan-400" : "border-transparent text-slate-400"}`}
            >
              Optimized Controls
            </button>
          </div>

          {/* Panel 1: Summary Terstruktur & Interactive Nodes (Poin 3 & 4) */}
          {activeTabPanel === "metrics" && (
            <div className="space-y-6">
              {/* Summary Narrative Terstruktur (Poin 3) */}
              <div className="bg-slate-900 border border-slate-800 p-5 rounded-xl space-y-3">
                <h3 className="text-xs font-semibold text-slate-400 uppercase tracking-wider flex items-center gap-2">
                  <Info size={14} className="text-cyan-400" /> Simulation Executive Summary
                </h3>
                <div className="grid grid-cols-1 md:grid-cols-3 gap-4 pt-2 border-t border-slate-800/80 text-xs">
                  <div>
                    <span className="text-slate-500 block text-[10px] uppercase">Blocked Techniques</span>
                    <span className="font-mono font-bold text-slate-200">{simulationData.blocked_techniques.join(", ") || "None"}</span>
                  </div>
                  <div>
                    <span className="text-slate-500 block text-[10px] uppercase">Removed Nodes Count</span>
                    <span className="font-mono font-bold text-rose-400">{simulationData.removed_nodes.length} nodes</span>
                  </div>
                  <div>
                    <span className="text-slate-500 block text-[10px] uppercase">Attack Chain Status</span>
                    <span className="font-bold text-cyan-300">{simulationData.metrics_before.risk_score > simulationData.metrics_after.risk_score ? "Degraded / Mitigated" : "Still Viable"}</span>
                  </div>
                </div>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                {/* Remaining Nodes dengan Interactive Badge (Poin 4) */}
                <div className="bg-slate-900 border border-slate-800 p-5 rounded-xl">
                  <h3 className="text-xs font-semibold text-emerald-400 flex items-center gap-2 mb-3 uppercase tracking-wider">
                    <ShieldCheck size={16} /> Remaining Attack Nodes ({simulationData.remaining_nodes.length})
                  </h3>
                  <p className="text-[11px] text-slate-500 mb-3">Klik node di bawah untuk melihat detail teknik mitigasinya.</p>
                  <div className="flex flex-wrap gap-2 mb-4">
                    {simulationData.remaining_nodes.map(nodeId => (
                      <button 
                        key={nodeId} 
                        onClick={() => setSelectedNodeId(nodeId)}
                        className={`px-3 py-1.5 rounded-lg text-xs font-mono transition cursor-pointer border ${selectedNodeId === nodeId ? 'bg-cyan-950 border-cyan-600 text-cyan-300 shadow-md' : 'bg-slate-800 border-slate-700 text-slate-300 hover:bg-slate-700'}`}
                      >
                        {nodeId}
                      </button>
                    ))}
                  </div>

                  {/* Detail Box untuk Node yang diklik (Poin 4) */}
                  {selectedNodeId && (
                    <div className="bg-slate-950 border border-slate-800 p-4 rounded-xl text-xs space-y-2">
                      <div className="flex justify-between items-center text-slate-400 border-b border-slate-800 pb-1.5">
                        <span className="font-bold text-cyan-400">Node Detail: {selectedNodeId}</span>
                        <span className="text-[10px] bg-emerald-950 text-emerald-400 border border-emerald-900 px-2 py-0.5 rounded">Remaining</span>
                      </div>
                      <div className="grid grid-cols-2 gap-2 pt-1">
                        <div>
                          <span className="text-slate-500 text-[10px] block">Technique ID</span>
                          <span className="font-mono text-slate-200">T1059 / T1078</span>
                        </div>
                        <div>
                          <span className="text-slate-500 text-[10px] block">Tactic</span>
                          <span className="text-slate-200">Execution / Access</span>
                        </div>
                      </div>
                    </div>
                  )}
                </div>

                {/* Disrupted / Removed Nodes */}
                <div className="bg-slate-900 border border-slate-800 p-5 rounded-xl">
                  <h3 className="text-xs font-semibold text-rose-400 flex items-center gap-2 mb-3 uppercase tracking-wider">
                    <ShieldAlert size={16} /> Disrupted / Removed Nodes ({simulationData.removed_nodes.length})
                  </h3>
                  {simulationData.removed_nodes.length === 0 ? (
                    <p className="text-slate-500 text-xs italic">Tidak ada node yang terdisrupsi pada simulasi ini.</p>
                  ) : (
                    <div className="space-y-2 max-h-56 overflow-y-auto pr-1">
                      {simulationData.removed_nodes.map((node, idx) => (
                        <div key={idx} className="bg-slate-950/60 border border-slate-800 p-2.5 rounded-lg text-xs flex justify-between items-center">
                          <div>
                            <span className="font-mono text-rose-300 font-bold">{node.step_id}</span>
                            <span className="text-slate-400 ml-2 font-mono text-[11px]">({node.technique})</span>
                          </div>
                          <span className="bg-rose-950/80 text-rose-300 border border-rose-900 px-2 py-0.5 rounded text-[10px]">
                            {node.reason}
                          </span>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              </div>
            </div>
          )}

          {/* Panel 2: Comparison Table dengan Warna & Icon Dinamis (Poin 1) */}
          {activeTabPanel === "table" && (
            <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-xl">
              <table className="w-full text-left border-collapse text-xs">
                <thead>
                  <tr className="bg-slate-950 text-slate-400 border-b border-slate-800 uppercase tracking-wider text-[10px]">
                    <th className="p-4 font-semibold">Metric</th>
                    <th className="p-4 font-semibold">Before</th>
                    <th className="p-4 font-semibold">After</th>
                    <th className="p-4 font-semibold">Delta Change (Δ)</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800">
                  <DeltaRow 
                    label="Risk Score" 
                    before={simulationData.metrics_before.risk_score} 
                    after={simulationData.metrics_after.risk_score} 
                    delta={simulationData.comparison.risk_score_reduction} 
                    isLowerBetter 
                  />
                  <DeltaRow 
                    label="Severity" 
                    before={simulationData.metrics_before.severity} 
                    after={simulationData.metrics_after.severity} 
                    deltaStr={simulationData.comparison.severity_change} 
                  />
                  <DeltaRow 
                    label="Node Count" 
                    before={simulationData.metrics_before.node_count} 
                    after={simulationData.metrics_after.node_count} 
                    delta={simulationData.comparison.node_reduction} 
                    isLowerBetter 
                  />
                  <DeltaRow 
                    label="Edge Count" 
                    before={simulationData.metrics_before.edge_count} 
                    after={simulationData.metrics_after.edge_count} 
                    delta={simulationData.comparison.edge_reduction} 
                    isLowerBetter 
                  />
                  <DeltaRow 
                    label="Critical Path Length" 
                    before={simulationData.metrics_before.critical_path.length} 
                    after={simulationData.metrics_after.critical_path.length} 
                    delta={simulationData.comparison.critical_path_reduction} 
                    isLowerBetter 
                  />
                </tbody>
              </table>
            </div>
          )}

          {/* Panel 3: Optimized Controls dengan Enhanced Empty State (Poin 5) */}
          {activeTabPanel === "controls" && (
            <div className="bg-slate-900 border border-slate-800 p-6 rounded-xl space-y-4">
              <h3 className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Recommended Defense Controls</h3>
              {simulationData.optimized_controls && simulationData.optimized_controls.length > 0 ? (
                <div className="space-y-2">
                  {simulationData.optimized_controls.map((ctrl, idx) => (
                    <div key={idx} className="bg-slate-950 border border-slate-800 p-3 rounded-lg flex items-center justify-between text-xs">
                      <span className="font-medium text-emerald-400 flex items-center gap-2">
                        <CheckCircle size={14} /> {ctrl}
                      </span>
                    </div>
                  ))}
                </div>
              ) : (
                /* Enhanced Empty State (Poin 5) */
                <div className="bg-slate-950 border border-slate-800/80 p-6 rounded-xl text-center space-y-3">
                  <div className="inline-flex p-3 rounded-full bg-slate-900 text-amber-400 border border-slate-800">
                    <AlertTriangle size={20} />
                  </div>
                  <h4 className="text-xs font-bold text-slate-300">No optimized controls generated.</h4>
                  <p className="text-[11px] text-slate-500 max-w-md mx-auto leading-relaxed">
                    Reason: The blocked techniques are not present in the current attack graph. Coba masukkan teknik mitigasi yang valid sesuai graph untuk melihat rekomendasi kontrol pertahanan.
                  </p>
                </div>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

interface MetricCardProps {
  title: string;
  before: string | number;
  after: string | number;
  reduction?: number | string;
  isText?: boolean;
}

function MetricCard({ title, before, after, reduction, isText }: MetricCardProps) {
  return (
    <div className="bg-slate-900 border border-slate-800 p-5 rounded-xl flex flex-col justify-between shadow-xl">
      <span className="text-[11px] font-medium text-slate-400 uppercase tracking-wider">{title}</span>
      <div className="flex items-baseline justify-between mt-3">
        <div className="flex items-baseline gap-2">
          <span className="text-2xl font-bold text-slate-100 font-mono">{after}</span>
          {!isText && <span className="text-xs text-slate-500 line-through font-mono">{before}</span>}
        </div>
        {reduction !== undefined && reduction !== 0 && (
          <span className="text-[11px] font-semibold text-emerald-400 bg-emerald-950/60 border border-emerald-900 px-2 py-0.5 rounded flex items-center gap-1 font-mono">
            <ArrowDown size={10} /> {reduction}
          </span>
        )}
      </div>
    </div>
  );
}

interface DeltaRowProps {
  label: string;
  before: string | number;
  after: string | number;
  delta?: number;
  deltaStr?: string;
  isLowerBetter?: boolean;
}

function DeltaRow({ label, before, after, delta, deltaStr, isLowerBetter = false }: DeltaRowProps) {
  let badgeColor = "text-slate-400 bg-slate-800/50 border-slate-700";
  let icon = <Minus size={12} />;

  if (delta !== undefined) {
    if (delta > 0) {
      if (isLowerBetter) {
        badgeColor = "text-emerald-400 bg-emerald-950/60 border-emerald-900";
        icon = <ArrowDown size={12} />;
      } else {
        badgeColor = "text-emerald-400 bg-emerald-950/60 border-emerald-900";
        icon = <ArrowUp size={12} />;
      }
    } else if (delta < 0) {
      badgeColor = "text-rose-400 bg-rose-950/60 border-rose-900";
      icon = <ArrowUp size={12} />;
    }
  }

  return (
    <tr>
      <td className="p-4 font-medium text-slate-300">{label}</td>
      <td className="p-4 font-mono">{before}</td>
      <td className="p-4 font-mono font-bold text-cyan-400">{after}</td>
      <td className="p-4 font-mono">
        {deltaStr ? (
          <span className="text-slate-400">{deltaStr}</span>
        ) : (
          <span className={`inline-flex items-center gap-1 px-2.5 py-1 rounded border text-[11px] font-semibold ${badgeColor}`}>
            {icon} {delta === 0 ? "0" : delta}
          </span>
        )}
      </td>
    </tr>
  );
}