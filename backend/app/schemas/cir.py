from datetime import datetime
from typing import Any, List, Literal, Optional

from pydantic import BaseModel, Field, field_validator


EntityType = Literal[
    "threat_actor",
    "technique",
    "tactic",
    "asset",
    "identity",
    "vulnerability",
    "observable",
    "detection_rule",
    "defensive_control",
    "trust_zone",
    "evidence",
    "malware",
    "intrusion_set",
]

RelationshipType = Literal[
    "USES",
    "TARGETS",
    "REQUIRES",
    "EXPLOITS",
    "PRODUCES",
    "DETECTED_BY",
    "COUNTERED_BY",
    "CONNECTED_TO",
]

ValidationState = Literal[
    "UNVERIFIED",
    "LLM_INFERRED",
    "ATTACK_VERIFIED",
    "HUMAN_VERIFIED",
    "REJECTED",
]


class CIREntity(BaseModel):
    id: str
    entity_type: EntityType
    stix_id: Optional[str] = None
    stix_type: Optional[str] = None
    name: Optional[str] = None
    description: Optional[str] = None
    attributes: dict[str, Any] = Field(default_factory=dict)
    provenance: Optional[str] = None
    confidence: Optional[float] = Field(default=None, ge=0, le=1)
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    observed_at: Optional[datetime] = None
    stix_data: dict[str, Any] = Field(default_factory=dict)


ThreatActor = CIREntity
Technique = CIREntity
Tactic = CIREntity
Asset = CIREntity
Identity = CIREntity
Vulnerability = CIREntity
Observable = CIREntity
DetectionRule = CIREntity
DefensiveControl = CIREntity
TrustZone = CIREntity

# ===========================
# Evidence
# ===========================


class Evidence(BaseModel):
    type: Optional[str] = "unknown"
    evidence_text: Optional[str] = None
    description: Optional[str] = None
    source: Optional[str] = None
    timestamp: Optional[datetime] = None
    telemetry_source: Optional[str] = None
    asset: Optional[str] = None
    inference_method: Optional[str] = None
    validation_state: ValidationState = "UNVERIFIED"
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
    provenance: Optional[str] = None
    confidence: Optional[float] = Field(default=None, ge=0, le=1)
    created_at: Optional[datetime] = None
    observed_at: Optional[datetime] = None


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
    entity_refs: List[str] = Field(default_factory=list)
    provenance: Optional[str] = None
    confidence: Optional[float] = Field(default=None, ge=0, le=1)
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    observed_at: Optional[datetime] = None
    technique_name: Optional[str] = None
    tactic_name: Optional[str] = None
    attack_version: Optional[str] = None
    attack_data_sources: List[str] = Field(default_factory=list)
    technique_deprecated: bool = False
    technique_criticality: float = Field(default=1.0, ge=0, le=1)
    asset_criticality: float = Field(default=1.0, ge=0, le=1)
    attack_path_criticality: float = Field(default=1.0, ge=0, le=1)
    reachability: float = Field(default=1.0, ge=0, le=1)
    impact: float = Field(default=1.0, ge=0, le=1)
    probability: float = Field(default=1.0, ge=0, le=1)
    trust_boundary_crossings: float = Field(default=0.0, ge=0, le=1)
    crown_jewel_exposure: float = Field(default=0.0, ge=0, le=1)

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


class CIRRelationship(BaseModel):
    source: str = Field(alias="from")
    target: str = Field(alias="to")
    relationship: str
    stix_id: Optional[str] = None
    provenance: Optional[str] = None
    confidence: Optional[float] = Field(default=None, ge=0, le=1)
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    observed_at: Optional[datetime] = None
    stix_data: dict[str, Any] = Field(default_factory=dict)

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
    cir_version: str = "2.0"
    scenario_id: str
    attack_graph: AttackGraph
    attack_version: Optional[str] = None
    entities: List[CIREntity] = Field(default_factory=list)
    relationships: List[CIRRelationship] = Field(default_factory=list)
    provenance: Optional[str] = None
    confidence: Optional[float] = Field(default=None, ge=0, le=1)
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    observed_at: Optional[datetime] = None
