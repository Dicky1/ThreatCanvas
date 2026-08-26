from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.repositories.scenario_repo import ScenarioRepository
from app.schemas.cir import CIRSpecification
from app.schemas.detection import DetectionValidationRequest, DetectionValidationResult
from app.services.detection_validator import DetectionValidationService
from app.services.sigma_compiler import SigmaCompiler
from app.services.kql_compiler import KQLCompiler  # Pastikan file ini sudah ada
from app.services.spl_compiler import SPLCompiler  # Pastikan file ini sudah ada
from pydantic import BaseModel
from app.models.experiment import ExperimentMetric
from time import perf_counter

router = APIRouter()


class CompilerResponse(BaseModel):
    artifact_type: str
    content: str
    state: str = "GENERATED"


@router.get("/compile/{type}/{scenario_id}", response_model=CompilerResponse)
def compile_artifact(type: str, scenario_id: str, db: Session = Depends(get_db)):
    repo = ScenarioRepository(db)
    record = repo.get_by_id(scenario_id)

    if not record:
        raise HTTPException(status_code=404, detail="Scenario tidak ditemukan")

    try:
        # Konversi data database ke model CIRSpecification
        cir_data = CIRSpecification(**record.cir_graph_data)

        # Routing compiler berdasarkan tipe yang diminta
        if type == "sigma":
            content = SigmaCompiler(cir_data).compile()
        elif type == "kql":
            content = KQLCompiler(cir_data).compile()
        elif type == "spl":
            content = SPLCompiler(cir_data).compile()
        else:
            raise HTTPException(
                status_code=400,
                detail="Tipe artifact tidak didukung. Gunakan: sigma, kql, atau spl.",
            )

        return CompilerResponse(artifact_type=type, content=content, state="GENERATED")

    except Exception as e:
        # Log error untuk debugging di terminal
        print(f"Error compiling {type}: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Gagal mengompilasi: {str(e)}")


@router.post("/validate/{type}/{scenario_id}", response_model=DetectionValidationResult)
def validate_artifact(
    type: str,
    scenario_id: str,
    request: DetectionValidationRequest,
    db: Session = Depends(get_db),
):
    started = perf_counter()
    repo = ScenarioRepository(db)
    record = repo.get_by_id(scenario_id)
    if not record:
        raise HTTPException(status_code=404, detail="Scenario tidak ditemukan")
    try:
        cir_data = CIRSpecification(**record.cir_graph_data)
        compilers = {"sigma": SigmaCompiler, "kql": KQLCompiler, "spl": SPLCompiler}
        if type not in compilers:
            raise HTTPException(status_code=400, detail="Tipe artifact tidak didukung")
        content = compilers[type](cir_data).compile()
        technique_id = cir_data.attack_graph.nodes[0].technique if cir_data.attack_graph.nodes else None
        result = DetectionValidationService().validate(
            type, content, technique_id=technique_id, events=request.events or None
        )
        db.add(ExperimentMetric(
            scenario_id=scenario_id,
            operation="detection_validation",
            duration_ms=round((perf_counter() - started) * 1000, 2),
            status=result.state.lower(),
            details={
                "detection_precision": result.metrics.precision,
                "detection_recall": result.metrics.recall,
                "detection_f1": result.metrics.f1,
                "tp": result.metrics.tp,
                "fp": result.metrics.fp,
                "tn": result.metrics.tn,
                "fn": result.metrics.fn,
            },
        ))
        db.commit()
        return result
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Validasi detection gagal: {e}") from e
