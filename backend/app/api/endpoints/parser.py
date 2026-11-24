import logging
from time import perf_counter

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.api.deps import get_current_user, get_owned_cir, get_owned_scenario
from app.core.database import get_db
from app.models.experiment import ExperimentMetric
from app.models.scenario import ScenarioRecord
from app.models.user import UserRecord
from app.repositories.scenario_repo import ScenarioRepository
from app.schemas.cir import CIRSpecification, Evidence
from app.services.attack_knowledge import ATTACKKnowledgeService
from app.services.cir_pipeline import (
    PipelineResult,
    PipelineValidationError,
    generate_cir,
)
from app.services.llm_parser import LLMUnavailableError, parse_narrative_to_cir

router = APIRouter()
logger = logging.getLogger(__name__)
attack_knowledge = ATTACKKnowledgeService()


class ParseRequest(BaseModel):
    scenario: str = Field(..., max_length=10000, description="Narasi ancaman maksimal 10.000 karakter")


class RepairAttempt(BaseModel):
    attempt: int
    stage: str  # "schema" (LLM output not a CIR) or "validation" (CIR failed checks)
    errors: list[str]


class ParseResponse(BaseModel):
    cir: CIRSpecification
    validation: dict
    id: str
    repair_attempts: list[RepairAttempt] = []


def record_metric(db: Session, started: float, operation: str, status: str, **fields) -> None:
    db.add(ExperimentMetric(
        operation=operation,
        duration_ms=round((perf_counter() - started) * 1000, 2),
        status=status,
        **fields,
    ))
    db.commit()


async def run_llm_pipeline(text: str, generator, db: Session, started: float, operation: str) -> PipelineResult:
    """generate_cir with the HTTP error mapping shared by every LLM endpoint."""
    try:
        return await generate_cir(text, generator, attack_knowledge)
    except LLMUnavailableError as error:
        record_metric(db, started, operation, "error", details={"reason": "llm_unavailable"})
        raise HTTPException(status_code=502, detail="AI provider tidak dapat dihubungi. Coba lagi nanti.") from error
    except PipelineValidationError as error:
        record_metric(db, started, operation, "validation_failed", details={"status_code": 400, "attempts": len(error.attempts)})
        raise HTTPException(
            status_code=400,
            detail={
                "message": "Validation Failed",
                "validation": error.validation,
                "repair_attempts": [a.model_dump() for a in error.attempts],
            },
        ) from error
    except Exception as error:
        logger.error("Error pada pipeline %s: %s", operation, error, exc_info=True)
        record_metric(db, started, operation, "error", details={"reason": "internal"})
        raise HTTPException(status_code=500, detail="Gagal memproses skenario. Terjadi kesalahan internal server.") from error


def save_result(
    db: Session,
    started: float,
    operation: str,
    original_input: str,
    cir: CIRSpecification,
    validation: dict,
    owner_id: str,
    attempts: list | None = None,
    extra_details: dict | None = None,
) -> dict:
    saved_record = ScenarioRepository(db).save_scenario(
        original_input=original_input,
        cir_graph_data=cir.model_dump(mode="json"),
        owner_id=owner_id,
    )
    attempts = attempts or []
    record_metric(
        db,
        started,
        operation,
        "success",
        scenario_id=str(saved_record.id),
        node_count=len(cir.attack_graph.nodes),
        edge_count=len(cir.attack_graph.edges),
        details={"validation_valid": True, "repair_attempts": len(attempts), **(extra_details or {})},
    )
    return {
        "cir": cir,
        "validation": validation,
        "id": str(saved_record.id),
        "repair_attempts": [a.model_dump() for a in attempts],
    }


@router.post("/parse", response_model=ParseResponse)
async def parse_scenario(
    request: ParseRequest,
    db: Session = Depends(get_db),
    current_user: UserRecord = Depends(get_current_user),
):
    if not request.scenario.strip():
        raise HTTPException(status_code=400, detail="Scenario cannot be empty")
    started = perf_counter()
    # Looked up at call time so tests can substitute the LLM.
    result = await run_llm_pipeline(request.scenario, parse_narrative_to_cir, db, started, "parse")
    return save_result(db, started, "parse", request.scenario, result.cir, result.validation, current_user.id, result.attempts)


@router.get("/scenarios")
def get_all_scenarios(
    db: Session = Depends(get_db),
    current_user: UserRecord = Depends(get_current_user),
):
    return ScenarioRepository(db).list_for_owner(current_user.id)


@router.get("/scenarios/{scenario_id}")
def get_scenario(scenario: ScenarioRecord = Depends(get_owned_scenario)):
    return scenario


@router.get("/scenarios/{scenario_id}/evidence", response_model=list[Evidence])
def get_scenario_evidence(cir: CIRSpecification = Depends(get_owned_cir)):
    return [
        evidence
        for node in cir.attack_graph.nodes
        for evidence in node.evidence
    ]


@router.delete("/scenarios/{scenario_id}")
def delete_scenario(
    scenario_id: str,
    db: Session = Depends(get_db),
    current_user: UserRecord = Depends(get_current_user),
):
    if not ScenarioRepository(db).delete(scenario_id, current_user.id):
        raise HTTPException(status_code=404, detail="Scenario not found")
    return {"message": "Scenario deleted successfully"}
