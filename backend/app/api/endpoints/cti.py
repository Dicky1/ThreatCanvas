from fastapi import APIRouter, HTTPException

from app.schemas.cti import CTIFetchRequest, CTIFetchResult
from app.services.cti_connectors import CTIConnectorService

router = APIRouter(prefix="/cti", tags=["CTI Connectors"])


@router.post("/fetch", response_model=CTIFetchResult)
def fetch_cti(request: CTIFetchRequest):
    try:
        return CTIConnectorService().fetch(request)
    except Exception as error:
        raise HTTPException(status_code=400, detail=str(error)) from error
