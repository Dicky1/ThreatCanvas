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
    attack_complexity: float
    attack_maturity: str
