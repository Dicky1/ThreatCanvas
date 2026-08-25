export type RuleState =
  | 'GENERATED'
  | 'SYNTAX_VALID'
  | 'TESTED'
  | 'PRODUCTION_CANDIDATE'
  | 'FAILED';

export type ValidationState =
  | 'UNVERIFIED'
  | 'LLM_INFERRED'
  | 'ATTACK_VERIFIED'
  | 'HUMAN_VERIFIED'
  | 'REJECTED';

export interface Evidence {
  type?: string;
  evidence_text?: string;
  description?: string;
  source?: string;
  timestamp?: string;
  telemetry_source?: string;
  asset?: string;
  inference_method?: string;
  validation_state?: ValidationState;
  confidence?: number;
  [key: string]: unknown;
}

export interface CIRNode {
  step_id: string;
  tactic: string;
  technique: string;
  actor?: string | null;
  target: string;
  action_type: string;
  evidence: Evidence[];
  entity_refs?: string[];
  technique_name?: string | null;
  tactic_name?: string | null;
  attack_version?: string | null;
  attack_data_sources?: string[];
  confidence?: number | null;
  [key: string]: unknown;
}

export interface CIRGraph {
  nodes: CIRNode[];
  edges: Array<{ from: string; to: string; relationship: string }>;
}

export interface CIRSpecification {
  cir_version: string;
  scenario_id: string;
  attack_graph: CIRGraph;
  attack_version?: string | null;
  entities?: Array<Record<string, unknown>>;
  relationships?: Array<Record<string, unknown>>;
  confidence?: number | null;
}

export interface Scenario {
  id: string;
  original_input: string;
  created_at: string;
  cir_graph_data?: CIRSpecification;
}

export interface CoverageReport {
  overall_score: number;
  threat_completeness: number;
  graph_integrity: number;
  total_nodes: number;
  total_edges: number;
  covered_tactics: string[];
  missing_tactics: string[];
  covered_techniques: string[];
  recommendations: string[];
}

export interface GraphAnalysis {
  node_count: number;
  edge_count: number;
  critical_path: string[];
  attack_chains?: string[][];
  detection_choke_points: string[];
  high_risk_nodes: Array<{ node_id: string; score?: number }>;
  entry_points: string[];
  exit_points: string[];
  attack_maturity: string;
  attack_complexity: number;
  kill_chain_completion: number;
  coverage_percentage: number;
  blast_radius: Array<{ node_id: string; impacted_count: number; impacted_nodes: string[] }>;
  asset_risk_signals?: Array<{
    node_id: string;
    asset: string;
    asset_criticality: number;
    crown_jewel_exposure: number;
    risk_score: number;
  }>;
  trust_boundary_signals?: Array<{
    node_id: string;
    crossing_score: number;
    severity: string;
  }>;
  critical_path_explanation?: {
    path: string[];
    criticality_score: number;
    reasons: string[];
    missing_detection_nodes: string[];
    crown_jewel_nodes: string[];
    trust_boundary_nodes: string[];
    high_risk_nodes: string[];
  };
  missing_detection_details?: Array<{
    node_id: string;
    technique: string;
    action_type: string;
    target: string;
    reason: string;
  }>;
  most_likely_path?: {
    path: string[];
    probability: number;
    impact_score: number;
    risk_score: number;
    assumption: string;
  } | null;
  longest_chain: number;
  shortest_chain: number;
  graph_density: number;
  connected_components: number;
  average_degree: number;
}

export interface DetectionMetrics {
  tp: number;
  fp: number;
  tn: number;
  fn: number;
  precision: number;
  recall: number;
  f1: number;
}

export interface DetectionValidationResult {
  artifact_type: 'sigma' | 'kql' | 'spl';
  state: RuleState;
  stage_results: Record<string, boolean>;
  errors: string[];
  metrics: DetectionMetrics;
}

export interface SimulationResult {
  blocked_techniques: string[];
  removed_nodes: Array<{ step_id: string; technique: string; tactic?: string; reason: string }>;
  removed_edges: Array<Record<string, unknown>>;
  remaining_nodes: string[];
  metrics_before: Record<string, unknown>;
  metrics_after: Record<string, unknown>;
  comparison: Record<string, unknown>;
  risk_reduction: number;
  attack_path_disruption_score: number;
  optimized_controls: Array<Record<string, unknown>>;
  simulation_summary: string;
  rw_apds?: {
    baseline_risk: number;
    residual_risk: number;
    attack_paths_eliminated: string[][];
    critical_paths_eliminated: string[][];
    weighted_node_disruption: number;
    score: number;
    weights: Record<string, number>;
  };
}

export interface CollectiveDefenseResult {
  shared_techniques: Array<{
    technique_id: string;
    confidence: number;
    source_packages: string[];
    provenance: string[];
  }>;
  sanitized_indicators: Array<Record<string, unknown>>;
  shared_attack_paths: Array<{
    techniques: string[];
    confidence: number;
    source_packages: string[];
  }>;
  collective_graph: {
    nodes: Array<{
      technique_id: string;
      observed_by_count: number;
      confidence: number;
      source_packages: string[];
      emerging: boolean;
    }>;
    edges: Array<{
      source: string;
      target: string;
      observed_by_count: number;
      confidence: number;
      source_packages: string[];
    }>;
  };
  coverage: {
    observed_techniques: string[];
    local_techniques: string[];
    collective_detected_techniques: string[];
    collective_techniques: string[];
    local_coverage: number;
    collective_coverage: number;
    detection_gap_techniques: string[];
  };
  recommended_controls: Record<string, string[]>;
}

export interface CTIFetchResult {
  source_type: 'taxii' | 'misp' | 'opencti' | 'stix';
  object_count: number;
  technique_count: number;
  indicator_count: number;
  techniques: string[];
  indicators: Array<Record<string, unknown>>;
  normalized_bundle: Record<string, unknown>;
}

export interface ConsensusResult {
  model_count: number;
  consensus_confidence: number;
  techniques: Array<{
    technique_id: string;
    consensus_confidence: number;
    model_votes: Record<string, number>;
  }>;
  agreed_techniques: string[];
  disputed_techniques: string[];
}

export interface AttackTimeline {
  scenario_id: string;
  events: Array<{
    timestamp: string;
    node_id: string;
    technique: string;
    tactic: string;
    action_type: string;
    target: string;
    status: 'active' | 'blocked' | 'unreachable';
  }>;
}

export interface ExperimentRun {
  operation: string;
  duration_ms: number;
  status: string;
  node_count?: number;
  edge_count?: number;
  details: Record<string, unknown>;
  created_at: string;
}

export interface ResearchMetricResult {
  scenario_id: string;
  runs: ExperimentRun[];
}

export interface BenchmarkReport {
  summary: {
    scenario_count: number;
    cir_validity_rate: number;
    attack_precision: number;
    attack_recall: number;
    attack_f1: number;
    tactic_recall: number;
    graph_ordering_accuracy: number;
  };
  scenarios: Array<{
    scenario_id: string;
    cir_schema_valid: boolean;
    attack_precision: number;
    attack_recall: number;
    attack_f1: number;
    tactic_recall: number;
    graph_ordering_accuracy: number;
    expected_techniques: string[];
    predicted_techniques: string[];
    missing_techniques: string[];
    extra_techniques: string[];
  }>;
}
