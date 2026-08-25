import { useEffect, useState } from 'react';
import { FileText } from 'lucide-react';
import { api } from '../api/client';
import type { DetectionValidationResult } from '../types/api';
import { EmptyState, ErrorState, LoadingState, PageHeader, Panel, StatusBadge } from '../components/common/Primitives';
import { useThreatStore } from '../store/useThreatStore';

const formats = ['sigma', 'kql', 'spl'] as const;
export default function DetectionEngineering() {
  const { scenarioId, cirData, coverageData } = useThreatStore();
  const [format, setFormat] = useState<(typeof formats)[number]>('sigma');
  const [content, setContent] = useState('');
  const [validation, setValidation] = useState<DetectionValidationResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  useEffect(() => { if (!scenarioId) return; setLoading(true); setError(null); Promise.all([api.artifact(scenarioId, format), api.validateArtifact(scenarioId, format)]).then(([artifact, result]) => { setContent(artifact.content); setValidation(result); }).catch((reason) => setError(reason instanceof Error ? reason.message : 'Unable to load detection artifact.')).finally(() => setLoading(false)); }, [scenarioId, format]);
  const techniques = Array.from(new Map((cirData?.nodes ?? []).map((node) => [node.technique, node])).values());
  const covered = new Set(coverageData?.covered_techniques ?? []);
  return <div className="page-stack"><PageHeader eyebrow="Detection / Engineering" title="Detection Engineering" description="Review generated artifacts and explicit validation state before deployment." action={<span className="page-icon"><FileText size={18} /></span>} />{!scenarioId ? <EmptyState title="No active scenario" description="Analyze a scenario to generate backend-backed detection artifacts." /> : <><Panel title="Artifact workspace"><div className="segmented-control">{formats.map((item) => <button key={item} className={format === item ? 'active' : ''} onClick={() => setFormat(item)}>{item.toUpperCase()}</button>)}</div>{loading ? <LoadingState label="Loading artifact and validation" /> : error ? <ErrorState message={error} /> : <pre className="code-viewer"><code>{content || 'Not available'}</code></pre>}</Panel>{validation && <Panel title="Validation status" description="Generated rules are never treated as production-ready automatically."><div className="validation-grid">{Object.entries(validation.stage_results).map(([stage, passed]) => <div className="validation-item" key={stage}><span>{stage.replaceAll('_', ' ')}</span><StatusBadge tone={passed ? 'good' : 'danger'}>{passed ? 'PASS' : 'FAIL'}</StatusBadge></div>)}</div><div className="validation-summary"><StatusBadge tone={validation.state === 'PRODUCTION_CANDIDATE' ? 'good' : validation.state === 'FAILED' ? 'danger' : 'warn'}>{validation.state}</StatusBadge><span>TP {validation.metrics.tp} · FP {validation.metrics.fp} · TN {validation.metrics.tn} · FN {validation.metrics.fn}</span><span>Precision {(validation.metrics.precision * 100).toFixed(1)}% · Recall {(validation.metrics.recall * 100).toFixed(1)}% · F1 {(validation.metrics.f1 * 100).toFixed(1)}%</span></div></Panel>}{coverageData && techniques.length > 0 && <Panel title="Technique coverage mapping" description="Derived from the backend coverage response; it does not imply a validated detection rule for every technique."><div className="data-list">{techniques.map((node) => <div className="data-row" key={node.technique}><div><strong>{node.technique_name || node.technique}</strong><small>{node.tactic_name || node.tactic} · {node.target}</small></div><StatusBadge tone={covered.has(node.technique) ? 'good' : 'warn'}>{covered.has(node.technique) ? 'MAPPED' : 'NOT MAPPED'}</StatusBadge></div>)}</div></Panel>}</>}</div>;
}
