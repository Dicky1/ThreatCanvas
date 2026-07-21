from pydantic import BaseModel, Field, field_validator
from typing import List, Optional

# ===========================
# Evidence
# ===========================


class Evidence(BaseModel):
    type: Optional[str] = "unknown"
    description: Optional[str] = None
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
    evidence: List[Evidence] = Field(default_factory=list)

    @field_validator("evidence", mode="before")
    @classmethod
    def coerce_string_evidence(cls, v):
        if not v or not isinstance(v, list):
            return v

        def infer_type(text: str) -> str:
            t = text.lower()
            if any(
                k in t
                for k in ["c2", "connection", "http", "https", "traffic", "network"]
            ):
                return "network"
            if any(k in t for k in ["registry", "hkcu", "hklm"]):
                return "registry"
            if any(
                k in t
                for k in ["antivirus", "disabled", "process", "execution", "script"]
            ):
                return "process"
            if any(k in t for k in ["file", "encrypted", "attachment", "zip", "note"]):
                return "file"
            return "unknown"

        result = []
        for item in v:
            if isinstance(item, str):
                result.append({"type": infer_type(item), "description": item})
            else:
                result.append(item)
        return result


# ===========================
# Edge
# ===========================


class Edge(BaseModel):
    # Menggunakan alias agar frontend bisa tetap mengirim "from"
    source: str = Field(alias="from")
    target: str = Field(alias="to")
    relationship: str

    model_config = {"populate_by_name": True}


# ===========================
# Attack Graph
# ===========================


class AttackGraph(BaseModel):
    nodes: List[CIRNode]
    edges: List[Edge]


# ===========================
# Main Specification
# ===========================


class CIRSpecification(BaseModel):
    cir_version: str
    scenario_id: str
    attack_graph: AttackGraph
