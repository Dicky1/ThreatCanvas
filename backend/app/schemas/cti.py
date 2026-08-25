from typing import Any, Literal

from pydantic import BaseModel, Field


CTISourceType = Literal["taxii", "misp", "opencti", "stix"]


class CTIFetchRequest(BaseModel):
    source_type: CTISourceType
    url: str | None = None
    token: str | None = None
    payload: dict[str, Any] | None = None


class CTIFetchResult(BaseModel):
    source_type: CTISourceType
    object_count: int
    technique_count: int
    indicator_count: int
    techniques: list[str] = Field(default_factory=list)
    indicators: list[dict[str, Any]] = Field(default_factory=list)
    normalized_bundle: dict[str, Any]


class ConsensusCandidate(BaseModel):
    model_name: str
    confidence: float = Field(default=0.5, ge=0, le=1)
    cir: dict[str, Any]


class ConsensusRequest(BaseModel):
    candidates: list[ConsensusCandidate]


class ConsensusTechnique(BaseModel):
    technique_id: str
    consensus_confidence: float
    model_votes: dict[str, float]


class ConsensusResult(BaseModel):
    model_count: int
    consensus_confidence: float
    techniques: list[ConsensusTechnique]
    agreed_techniques: list[str]
    disputed_techniques: list[str]


class TimelineEvent(BaseModel):
    timestamp: str
    node_id: str
    technique: str
    tactic: str
    action_type: str
    target: str
    status: Literal["active", "blocked", "unreachable"] = "active"


class AttackTimeline(BaseModel):
    scenario_id: str
    events: list[TimelineEvent]
