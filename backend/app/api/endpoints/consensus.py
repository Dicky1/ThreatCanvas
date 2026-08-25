from fastapi import APIRouter, HTTPException

from app.schemas.cti import ConsensusRequest, ConsensusResult
from app.services.consensus import ConsensusService

router = APIRouter(prefix="/consensus", tags=["Consensus"])


@router.post("/analyze", response_model=ConsensusResult)
def analyze_consensus(request: ConsensusRequest):
    try:
        return ConsensusService().analyze(request)
    except Exception as error:
        raise HTTPException(status_code=400, detail=str(error)) from error
