import logging

from fastapi import APIRouter, Depends, HTTPException

from app.api.deps import get_owned_cir
from app.schemas.cir import CIRSpecification
from app.schemas.threat_reasoning import ThreatReasoning
from app.services.graph_analysis_engine import GraphAnalysisEngine
from app.services.threat_reasoning_engine import ThreatReasoningEngine

router = APIRouter()
reasoning_engine = ThreatReasoningEngine()
logger = logging.getLogger(__name__)


@router.get("/reasoning/{scenario_id}", response_model=ThreatReasoning)
def get_threat_reasoning(cir: CIRSpecification = Depends(get_owned_cir)):
    try:
        graph_data = GraphAnalysisEngine(cir_specification=cir).analyze()
        return reasoning_engine.generate_reasoning(cir=cir, graph_analysis=graph_data)
    except Exception as error:
        logger.error("Error reasoning: %s", error, exc_info=True)
        raise HTTPException(
            status_code=500,
            detail="Gagal menjalankan reasoning engine. Terjadi kesalahan internal.",
        ) from error
