from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session
from app.services.cir_validator import CIRValidator
from app.services.cir_normalizer import CIRNormalizer  # Import Normalizer baru
from app.services.attack_knowledge import ATTACKKnowledgeService

from app.core.database import get_db
from app.schemas.cir import CIRSpecification, Evidence
from app.services.evidence_provenance import EvidenceProvenanceEngine
from app.services.llm_parser import parse_narrative_to_cir
from app.repositories.scenario_repo import ScenarioRepository
from app.models.experiment import ExperimentMetric
from time import perf_counter

router = APIRouter()
attack_knowledge = ATTACKKnowledgeService()


class ParseRequest(BaseModel):
    scenario: str


class ParseResponse(BaseModel):
    cir: CIRSpecification
    validation: dict
    id: str


@router.post("/parse", response_model=ParseResponse)
async def parse_scenario(request: ParseRequest, db: Session = Depends(get_db)):
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
        # Tambahkan log di sini jika perlu untuk debugging
        print(f"Error pada pipeline: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/scenarios")
def get_all_scenarios(db: Session = Depends(get_db)):
    repo = ScenarioRepository(db)
    return repo.get_all()


@router.get("/scenarios/{scenario_id}")
def get_scenario(scenario_id: str, db: Session = Depends(get_db)):
    repo = ScenarioRepository(db)
    scenario = repo.get_by_id(scenario_id)

    if scenario is None:
        raise HTTPException(status_code=404, detail="Scenario not found")

    return scenario


@router.get("/scenarios/{scenario_id}/evidence", response_model=list[Evidence])
def get_scenario_evidence(scenario_id: str, db: Session = Depends(get_db)):
    cir = ScenarioRepository(db).get_cir(scenario_id)
    if cir is None:
        raise HTTPException(status_code=404, detail="Scenario not found")

    return [
        evidence
        for node in cir.attack_graph.nodes
        for evidence in node.evidence
    ]


@router.delete("/scenarios/{scenario_id}")
def delete_scenario(scenario_id: str, db: Session = Depends(get_db)):
    repo = ScenarioRepository(db)
    deleted = repo.delete(scenario_id)

    if not deleted:
        raise HTTPException(status_code=404, detail="Scenario not found")

    return {"message": "Scenario deleted successfully"}
