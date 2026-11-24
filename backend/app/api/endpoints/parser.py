from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session
from app.services.cir_validator import CIRValidator
from app.services.cir_normalizer import CIRNormalizer  # Import Normalizer baru
from app.services.attack_knowledge import ATTACKKnowledgeService

from app.api.deps import get_current_user, get_owned_cir, get_owned_scenario
from app.core.database import get_db
from app.models.scenario import ScenarioRecord
from app.models.user import UserRecord
from app.schemas.cir import CIRSpecification, Evidence
from app.services.evidence_provenance import EvidenceProvenanceEngine
from app.services.llm_parser import parse_narrative_to_cir
from app.repositories.scenario_repo import ScenarioRepository
from app.models.experiment import ExperimentMetric
from time import perf_counter

router = APIRouter()
attack_knowledge = ATTACKKnowledgeService()


from pydantic import Field
class ParseRequest(BaseModel):
    scenario: str = Field(..., max_length=10000, description="Narasi ancaman maksimal 10.000 karakter")


class ParseResponse(BaseModel):
    cir: CIRSpecification
    validation: dict
    id: str


@router.post("/parse", response_model=ParseResponse)
async def parse_scenario(
    request: ParseRequest,
    db: Session = Depends(get_db),
    current_user: UserRecord = Depends(get_current_user),
):
    if not request.scenario.strip():
        raise HTTPException(status_code=400, detail="Scenario cannot be empty")

    started = perf_counter()
    try:
        # 1. Generate Raw CIR dari LLM
        cir_graph = await parse_narrative_to_cir(request.scenario)

        # 2. Normalisasi (Translate istilah ke ID standar)
        # Sekarang "Phishing" akan menjadi "T1566" sebelum divalidasi
        cir_graph = CIRNormalizer.normalize(cir_graph, attack_knowledge)

        # 2b. Tambahkan provenance dan sanitasi evidence sebelum penyimpanan
        cir_graph = EvidenceProvenanceEngine.enrich(cir_graph)

        # 3. Validasi (Deterministic check)
        validation_result = CIRValidator.validate(cir_graph, attack_knowledge)

        # 4. Jika validasi gagal, kembalikan error
        if not validation_result["valid"]:
            raise HTTPException(
                status_code=400,
                detail={
                    "message": "Validation Failed",
                    "validation": validation_result,
                },
            )

        # 5. Simpan ke Database
        repo = ScenarioRepository(db)
        saved_record = repo.save_scenario(
            original_input=request.scenario,
            cir_graph_data=cir_graph.model_dump(mode="json"),
            owner_id=current_user.id,
        )

        db.add(ExperimentMetric(scenario_id=str(saved_record.id), operation="parse", duration_ms=round((perf_counter() - started) * 1000, 2), status="success", node_count=len(cir_graph.attack_graph.nodes), edge_count=len(cir_graph.attack_graph.edges), details={"validation_valid": validation_result.get("valid", False)}))
        db.commit()
        return {
            "cir": cir_graph,
            "validation": validation_result,
            "id": str(saved_record.id),
        }

    except HTTPException as he:
        db.add(ExperimentMetric(operation="parse", duration_ms=round((perf_counter() - started) * 1000, 2), status="validation_failed" if he.status_code == 400 else "error", details={"status_code": he.status_code}))
        db.commit()
        raise he
    except Exception as e:
        import logging
        logging.getLogger(__name__).error(f"Error pada pipeline parse: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Gagal memproses skenario. Terjadi kesalahan internal server.")


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
