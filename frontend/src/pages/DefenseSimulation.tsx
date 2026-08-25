import { Shield } from 'lucide-react';
import AttackSimulationView from '../components/AttackSimulationView';
import { EmptyState, PageHeader } from '../components/common/Primitives';
import { useThreatStore } from '../store/useThreatStore';

export default function DefenseSimulation() {
  const scenarioId = useThreatStore((state) => state.scenarioId);
  return <div className="page-stack"><PageHeader eyebrow="Defense / What-if" title="Defense Simulation" description="Measure structural disruption and risk-weighted impact using the backend simulation engine." action={<span className="page-icon"><Shield size={18} /></span>} />{scenarioId ? <AttackSimulationView scenarioId={scenarioId} /> : <EmptyState title="No active scenario" description="Analyze a scenario before running a defensive simulation." />}</div>;
}
