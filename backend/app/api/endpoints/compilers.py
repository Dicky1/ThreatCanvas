import logging
from time import perf_counter

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.api.deps import get_owned_cir
from app.core.database import get_db
from app.models.experiment import ExperimentMetric
from app.schemas.cir import CIRSpecification
from app.schemas.detection import DetectionValidationRequest, DetectionValidationResult
from app.services.detection_validator import DetectionValidationService
from app.services.kql_compiler import KQLCompiler
from app.services.sigma_compiler import SigmaCompiler
from app.services.spl_compiler import SPLCompiler

router = APIRouter()
logger = logging.getLogger(__name__)

COMPILERS = {"sigma": SigmaCompiler, "kql": KQLCompiler, "spl": SPLCompiler}


class CompilerResponse(BaseModel):
    artifact_type: str
    content: str
    state: str = "GENERATED"


def _compiler(artifact_type: str):
    compiler = COMPILERS.get(artifact_type)
    if compiler is None:
        raise HTTPException(
            status_code=400,
            detail="Tipe artifact tidak didukung. Gunakan: sigma, kql, atau spl.",
        )
    return compiler


@router.get("/compile/{type}/{scenario_id}", response_model=CompilerResponse)
def compile_artifact(type: str, cir_data: CIRSpecification = Depends(get_owned_cir)):
    compiler = _compiler(type)
    try:
        content = compiler(cir_data).compile()
    except Exception as error:
        logger.error("Error compiling %s: %s", type, error, exc_info=True)
        raise HTTPException(
            status_code=500,
            detail="Gagal mengompilasi artifact. Terjadi kesalahan internal server.",
        ) from error
    return CompilerResponse(artifact_type=type, content=content, state="GENERATED")


@router.post("/validate/{type}/{scenario_id}", response_model=DetectionValidationResult)
def validate_artifact(
    type: str,
    scenario_id: str,
    request: DetectionValidationRequest,
    db: Session = Depends(get_db),
    cir_data: CIRSpecification = Depends(get_owned_cir),
):
    compiler = _compiler(type)
    started = perf_counter()
    try:
        content = compiler(cir_data).compile()
        technique_id = cir_data.attack_graph.nodes[0].technique if cir_data.attack_graph.nodes else None
        result = DetectionValidationService().validate(
            type, content, technique_id=technique_id, events=request.events or None
        )
    except Exception as error:
        logger.error("Detection validation failed for %s: %s", type, error, exc_info=True)
        raise HTTPException(status_code=500, detail="Validasi detection gagal karena kesalahan internal.") from error

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
