from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field

TLPClassification = Literal["TLP:CLEAR", "TLP:GREEN", "TLP:AMBER", "TLP:RED"]


class Organization(BaseModel):
    organization_id: str
    name: str


class ThreatIntelligencePackage(BaseModel):
    package_id: str
    organization: Organization
    tlp: TLPClassification
    source_confidence: float = Field(..., ge=0, le=1)
    observed_techniques: list[str] = Field(default_factory=list)
    sanitized_indicators: list[dict[str, Any]] = Field(default_factory=list)
    observed_at: datetime | None = None
    provenance: str | None = None


class SharedTechnique(BaseModel):
    technique_id: str
    confidence: float
    source_packages: list[str]
    provenance: list[str] = Field(default_factory=list)
    observed_at: list[datetime] = Field(default_factory=list)


class SharedAttackPath(BaseModel):
    techniques: list[str]
    confidence: float
    source_packages: list[str]


class CoverageSummary(BaseModel):
    local_techniques: list[str]
    collective_techniques: list[str]
    local_coverage: float
    collective_coverage: float


class CollectiveGraphNode(BaseModel):
    technique_id: str
    observed_by_count: int
    confidence: float
    source_packages: list[str]
    emerging: bool


class CollectiveGraphEdge(BaseModel):
    source: str
    target: str
    observed_by_count: int
    confidence: float
    source_packages: list[str]


class CollectiveThreatGraph(BaseModel):
    nodes: list[CollectiveGraphNode]
    edges: list[CollectiveGraphEdge]


class CollectiveDefenseResult(BaseModel):
    shared_techniques: list[SharedTechnique]
    sanitized_indicators: list[dict[str, Any]]
    shared_attack_paths: list[SharedAttackPath]
    collective_graph: CollectiveThreatGraph
    coverage: CoverageSummary
    recommended_controls: dict[str, list[str]]
