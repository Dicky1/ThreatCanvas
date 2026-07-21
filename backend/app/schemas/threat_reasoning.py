from pydantic import BaseModel
from typing import List

class RiskNode(BaseModel):
    node_id: str
    technique_id: str
    tactic: str
    risk_level: str

class DetectionGap(BaseModel):
    technique_id: str
    technique_name: str
    status: str

class RankedPriority(BaseModel):
    technique_id: str
    technique_name: str
    risk_level: str

class ThreatReasoning(BaseModel):
    severity: str
    severity_score: int
    confidence: str
    attack_objective: str
    attack_complexity: str
    kill_chain_completion: str
    highest_risk_nodes: List[RiskNode]
    priority_ranking: List[RankedPriority]
    detection_gaps: List[DetectionGap]
    recommended_actions: List[str]
    recommended_controls: List[str]
    executive_summary: str