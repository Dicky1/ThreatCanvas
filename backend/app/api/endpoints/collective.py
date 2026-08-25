from fastapi import APIRouter, HTTPException

from app.schemas.collective import (
    CollectiveDefenseResult,
    ThreatIntelligencePackage,
)
from app.services.collective_defense import CollectiveDefenseEngine

router = APIRouter(prefix="/api/v1/collective", tags=["Collective Defense"])


@router.post("/analyze", response_model=CollectiveDefenseResult)
def analyze_collective_intelligence(payload: dict):
    try:
        packages = [
            ThreatIntelligencePackage.model_validate(item)
            for item in payload.get("packages", [])
        ]
        return CollectiveDefenseEngine().analyze(
            packages,
            payload.get("local_detected_techniques", []),
        )
    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error