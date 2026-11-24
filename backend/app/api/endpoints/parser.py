import logging
from functools import partial
from time import perf_counter

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.api.deps import get_current_user, get_owned_cir, get_owned_scenario
from app.core.database import get_db
from app.models.experiment import ExperimentMetric
from app.models.scenario import ScenarioRecord
from app.models.user import UserRecord
from app.models.workspace import Workspace
from app.repositories.scenario_repo import ScenarioRepository
from app.schemas.cir import CIRSpecification, Evidence
from app.services.attack_knowledge import ATTACKKnowledgeService
from app.services.cir_pipeline import (
    PipelineResult,
    PipelineValidationError,
    generate_cir,
)
from app.services.llm_client import UnknownProfileError, get_profile
from app.services.llm_parser import LLMUnavailableError, parse_narrative_to_cir

router = APIRouter()
logger = logging.getLogger(__name__)
attack_knowledge = ATTACKKnowledgeService()


class ParseRequest(BaseModel):
    scenario: str = Field(..., max_length=10000, description="Narasi ancaman maksimal 10.000 karakter")
    model_profile: str | None = Field(default=None, max_length=64, description="LLM profile name (GET /llm/profiles)")


def llm_generator(base, profile: str | None = None, instructions: str | None = None):
    """Bind the request's LLM profile / instructions to ``base`` (the LLM call).
    Unknown profiles are a 400 before any model is called."""
    try:
        get_profile(profile)
    except UnknownProfileError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error
    kwargs = {key: value for key, value in (("profile", profile), ("instructions", instructions)) if value}
    return partial(base, **kwargs) if kwargs else base


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
    # parse_narrative_to_cir is looked up at call time so tests can substitute the LLM.
    generator = llm_generator(parse_narrative_to_cir, request.model_profile)
    result = await run_llm_pipeline(request.scenario, generator, db, started, "parse")
    return save_result(db, started, "parse", request.scenario, result.cir, result.validation, current_user.id, result.attempts)


class WorkspaceAssignment(BaseModel):
    workspace_id: str | None = None


def _scenario_payloads(db: Session, scenarios: list[ScenarioRecord], user: UserRecord) -> list[dict]:
    repo = ScenarioRepository(db)
    owner_ids = {s.owner_id for s in scenarios if s.owner_id}
    workspace_ids = {s.workspace_id for s in scenarios if s.workspace_id}
    usernames = {u.id: u.username for u in db.query(UserRecord).filter(UserRecord.id.in_(owner_ids)).all()} if owner_ids else {}
    workspaces = {w.id: w.name for w in db.query(Workspace).filter(Workspace.id.in_(workspace_ids)).all()} if workspace_ids else {}
    return [
        {
            "id": scenario.id,
            "original_input": scenario.original_input,
            "created_at": scenario.created_at,
            "owner_id": scenario.owner_id,
            "owner_username": usernames.get(scenario.owner_id),
            "is_owner": scenario.owner_id == user.id,
            "workspace_id": scenario.workspace_id,
            "workspace_name": workspaces.get(scenario.workspace_id),
            "can_edit": repo.can_edit(scenario, user.id),
        }
        for scenario in scenarios
    ]


@router.get("/scenarios")
def get_all_scenarios(
    workspace: str | None = None,
    db: Session = Depends(get_db),
    current_user: UserRecord = Depends(get_current_user),
):
    """Own scenarios plus those shared into the caller's workspaces.
    ``workspace=personal`` or a workspace id narrows the list."""
    return _scenario_payloads(db, ScenarioRepository(db).list_for_owner(current_user.id, workspace), current_user)


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
    try:
        deleted = ScenarioRepository(db).delete(scenario_id, current_user.id)
    except PermissionError as error:
        raise HTTPException(status_code=403, detail=str(error)) from error
    if not deleted:
        raise HTTPException(status_code=404, detail="Scenario not found")
    return {"message": "Scenario deleted successfully"}


@router.put("/scenarios/{scenario_id}/workspace")
def set_scenario_workspace(
    request: WorkspaceAssignment,
    scenario: ScenarioRecord = Depends(get_owned_scenario),
    db: Session = Depends(get_db),
    current_user: UserRecord = Depends(get_current_user),
):
    """Share a scenario into a workspace (or back to personal with null)."""
    try:
        updated = ScenarioRepository(db).set_workspace(scenario, current_user.id, request.workspace_id)
    except PermissionError as error:
        raise HTTPException(status_code=403, detail=str(error)) from error
    return _scenario_payloads(db, [updated], current_user)[0]
