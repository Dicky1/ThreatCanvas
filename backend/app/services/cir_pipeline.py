"""LLM -> CIR pipeline with deterministic validation and self-repair.

Shared by /parse (narratives) and /ingest (CTI reports, SIEM alerts):
generate -> normalize -> provenance -> validate; failures are sent back to
the LLM with their errors up to LLM_REPAIR_ATTEMPTS times.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any

from app.core.config import settings
from app.schemas.cir import CIRSpecification
from app.services.attack_knowledge import ATTACKKnowledgeService
from app.services.cir_normalizer import CIRNormalizer
from app.services.cir_validator import CIRValidator
from app.services.evidence_provenance import EvidenceProvenanceEngine
from app.services.llm_parser import CIRGenerationError, RepairContext

Generator = Callable[..., Awaitable[CIRSpecification]]


@dataclass
class RepairAttemptRecord:
    attempt: int
    stage: str  # "schema" | "validation"
    errors: list[str]

    def model_dump(self) -> dict[str, Any]:
        return {"attempt": self.attempt, "stage": self.stage, "errors": self.errors}


@dataclass
class PipelineResult:
    cir: CIRSpecification
    validation: dict[str, Any]
    attempts: list[RepairAttemptRecord] = field(default_factory=list)


class PipelineValidationError(Exception):
    """Still invalid after every self-repair attempt."""

    def __init__(self, validation: dict[str, Any], attempts: list[RepairAttemptRecord]):
        super().__init__("CIR validation failed")
        self.validation = validation
        self.attempts = attempts


def finalize(cir: CIRSpecification, knowledge: ATTACKKnowledgeService) -> tuple[CIRSpecification, dict[str, Any]]:
    """Deterministic post-processing shared with non-LLM sources."""
    cir = CIRNormalizer.normalize(cir, knowledge)
    cir = EvidenceProvenanceEngine.enrich(cir)
    return cir, CIRValidator.validate(cir, knowledge)


async def generate_cir(text: str, generator: Generator, knowledge: ATTACKKnowledgeService) -> PipelineResult:
    """Run the LLM ``generator`` with self-repair.

    ``generator(text)`` / ``generator(text, repair=...)`` must return a CIR or
    raise CIRGenerationError (repairable) / LLMUnavailableError (not retried).
    """
    attempts: list[RepairAttemptRecord] = []
    repair: RepairContext | None = None
    validation: dict[str, Any] = {}
    for attempt in range(1, settings.LLM_REPAIR_ATTEMPTS + 2):
        try:
            candidate = await (generator(text) if repair is None else generator(text, repair=repair))
        except CIRGenerationError as error:
            attempts.append(RepairAttemptRecord(attempt, "schema", error.errors))
            repair = RepairContext(previous_output=error.raw_output, errors=error.errors)
            continue
        candidate, validation = finalize(candidate, knowledge)
        if validation["valid"]:
            return PipelineResult(candidate, validation, attempts)
        attempts.append(RepairAttemptRecord(attempt, "validation", validation["errors"]))
        repair = RepairContext(previous_output=candidate.model_dump_json(), errors=validation["errors"])
    raise PipelineValidationError(validation, attempts)
