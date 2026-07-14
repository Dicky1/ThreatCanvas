from pydantic import BaseModel, Field
from typing import List, Optional


# ===========================
# Evidence
# ===========================

class Evidence(BaseModel):
    type: Optional[str] = "unknown"

    image: Optional[str] = None
    command_line: Optional[str] = None
    filename: Optional[str] = None
    hash_sha256: Optional[str] = None
    registry_key: Optional[str] = None
    registry_value: Optional[str] = None
    ip: Optional[str] = None
    domain: Optional[str] = None
    url: Optional[str] = None
    protocol: Optional[str] = None


# ===========================
# Attack Node
# ===========================

class CIRNode(BaseModel):
    step_id: str

    tactic: str
    technique: str

    actor: Optional[str] = None
    target: str

    action_type: str

    evidence: List[Evidence] = []


# ===========================
# Edge
# ===========================

class Edge(BaseModel):
    from_node: str = Field(alias="from")
    to_node: str = Field(alias="to")
    relationship: str

    model_config = {
        "populate_by_name": True
    }

# ===========================
# Attack Graph
# ===========================

class AttackGraph(BaseModel):
    nodes: List[CIRNode]
    edges: List[Edge]

class CIRSpecification(BaseModel):
    cir_version: str
    scenario_id: str
    attack_graph: AttackGraph