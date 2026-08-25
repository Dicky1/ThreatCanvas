from typing import Any, Literal

from pydantic import BaseModel, Field

RuleState = Literal[
    "GENERATED",
    "SYNTAX_VALID",
    "TESTED",
    "PRODUCTION_CANDIDATE",
    "FAILED",
]


class DetectionEvent(BaseModel):
    event: dict[str, Any]
    malicious: bool
    technique_id: str | None = None


class DetectionValidationRequest(BaseModel):
    events: list[DetectionEvent] = Field(default_factory=list)


class DetectionMetrics(BaseModel):
    tp: int = 0
    fp: int = 0
    tn: int = 0
    fn: int = 0
    precision: float = 0.0
    recall: float = 0.0
    f1: float = 0.0


class DetectionValidationResult(BaseModel):
    artifact_type: Literal["sigma", "kql", "spl"]
    state: RuleState
    stage_results: dict[str, bool]
    errors: list[str] = Field(default_factory=list)
    metrics: DetectionMetrics