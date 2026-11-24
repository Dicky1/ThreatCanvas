import logging
from time import perf_counter

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.api.deps import get_current_user, get_owned_cir, get_owned_scenario
from app.core.config import settings
from app.core.database import get_db
from app.models.experiment import ExperimentMetric
from app.models.scenario import ScenarioRecord
from app.models.user import UserRecord
from app.repositories.scenario_repo import ScenarioRepository
from app.schemas.cir import CIRSpecification, Evidence
from app.services.attack_knowledge import ATTACKKnowledgeService
from app.services.cir_normalizer import CIRNormalizer  # Import Normalizer baru
from app.services.cir_validator import CIRValidator
from app.services.evidence_provenance import EvidenceProvenanceEngine
from app.services.llm_parser import (
    CIRGenerationError,
    LLMUnavailableError,
    RepairContext,
    parse_narrative_to_cir,
)

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


def _metric(db: Session, started: float, status: str, **fields) -> None:
    db.add(ExperimentMetric(
        operation="parse",
        duration_ms=round((perf_counter() - started) * 1000, 2),
        status=status,
        **fields,
    ))
    db.commit()


@router.post("/parse", response_model=ParseResponse)
async def parse_scenario(
    request: ParseRequest,
    db: Session = Depends(get_db),
    current_user: UserRecord = Depends(get_current_user),
):
    if not request.scenario.strip():
        raise HTTPException(status_code=400, detail="Scenario cannot be empty")

    started = perf_counter()
    attempts: list[RepairAttempt] = []
    repair: RepairContext | None = None
    cir_graph: CIRSpecification | None = None
    validation_result: dict = {}

    # 1 initial generation + up to LLM_REPAIR_ATTEMPTS self-repair rounds.
    for attempt in range(1, settings.LLM_REPAIR_ATTEMPTS + 2):
        try:
            if repair is None:
                candidate = await parse_narrative_to_cir(request.scenario)
            else:
                candidate = await parse_narrative_to_cir(request.scenario, repair=repair)
        except LLMUnavailableError as error:
            _metric(db, started, "error", details={"reason": "llm_unavailable", "attempts": attempt})
            raise HTTPException(status_code=502, detail="AI provider tidak dapat dihubungi. Coba lagi nanti.") from error
        except CIRGenerationError as error:
            attempts.append(RepairAttempt(attempt=attempt, stage="schema", errors=error.errors))
            repair = RepairContext(previous_output=error.raw_output, errors=error.errors)
            continue
        except Exception as error:
            logger.error("Error pada pipeline parse: %s", error, exc_info=True)
            _metric(db, started, "error", details={"reason": "internal"})
            raise HTTPException(
                status_code=500,
                detail="Gagal memproses skenario. Terjadi kesalahan internal server.",
            ) from error

        # Normalisasi -> provenance -> validasi deterministik
        try:
            candidate = CIRNormalizer.normalize(candidate, attack_knowledge)
            candidate = EvidenceProvenanceEngine.enrich(candidate)
            validation_result = CIRValidator.validate(candidate, attack_knowledge)
        except Exception as error:
            logger.error("Error pada normalisasi/validasi CIR: %s", error, exc_info=True)
            _metric(db, started, "error", details={"reason": "internal"})
            raise HTTPException(
                status_code=500,
                detail="Gagal memproses skenario. Terjadi kesalahan internal server.",
            ) from error
        cir_graph = candidate
        if validation_result["valid"]:
            break
        attempts.append(RepairAttempt(attempt=attempt, stage="validation", errors=validation_result["errors"]))
        repair = RepairContext(previous_output=candidate.model_dump_json(), errors=validation_result["errors"])
    else:
        _metric(db, started, "validation_failed", details={"status_code": 400, "attempts": len(attempts)})
        raise HTTPException(
            status_code=400,
            detail={
                "message": "Validation Failed",
                "validation": validation_result,
                "repair_attempts": [a.model_dump() for a in attempts],
            },
        )

    saved_record = ScenarioRepository(db).save_scenario(
        original_input=request.scenario,
        cir_graph_data=cir_graph.model_dump(mode="json"),
        owner_id=current_user.id,
    )
    _metric(
        db,
        started,
        "success",
        scenario_id=str(saved_record.id),
        node_count=len(cir_graph.attack_graph.nodes),
        edge_count=len(cir_graph.attack_graph.edges),
        details={"validation_valid": True, "repair_attempts": len(attempts)},
    )
    return {
        "cir": cir_graph,
        "validation": validation_result,
        "id": str(saved_record.id),
        "repair_attempts": attempts,
    }


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
