from pydantic import BaseModel
from typing import List


class HighRiskNode(BaseModel):
    node_id: str
    score: int
    matched_tactics: List[str]


class BlastRadius(BaseModel):
    node_id: str
    impacted_count: int
    impacted_nodes: List[str]


class AssetRiskSignal(BaseModel):
    node_id: str
    asset: str
    asset_criticality: float
    crown_jewel_exposure: float
    risk_score: float


class TrustBoundarySignal(BaseModel):
    node_id: str
    crossing_score: float
    severity: str


class CriticalPathExplanation(BaseModel):
    path: List[str]
    criticality_score: float
    reasons: List[str]
    missing_detection_nodes: List[str]
    crown_jewel_nodes: List[str]
    trust_boundary_nodes: List[str]
    high_risk_nodes: List[str]


class MissingDetectionDetail(BaseModel):
    node_id: str
    technique: str
    action_type: str
    target: str
    reason: str


class ProbabilisticPath(BaseModel):
    path: List[str]
    probability: float
    impact_score: float
    risk_score: float
    assumption: str


class AttackGraphAnalysis(BaseModel):
    node_count: int
    edge_count: int
    entry_points: List[str]
    exit_points: List[str]
    critical_path: List[str]
    attack_chains: List[List[str]]
    graph_density: float
    connected_components: int
    isolated_nodes: List[str]
    average_degree: float
    average_in_degree: float
    average_out_degree: float
    longest_chain: int
    shortest_chain: int
    kill_chain_completion: float
    coverage_percentage: float
    detection_choke_points: List[str]
    high_risk_nodes: List[HighRiskNode]
    blast_radius: List[BlastRadius]
    asset_risk_signals: List[AssetRiskSignal]
    trust_boundary_signals: List[TrustBoundarySignal]
    critical_path_explanation: CriticalPathExplanation
    missing_detection_details: List[MissingDetectionDetail]
    most_likely_path: ProbabilisticPath | None
    attack_complexity: float
    attack_maturity: str
