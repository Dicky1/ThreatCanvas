from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.api.deps import get_current_user, get_owned_cir
from app.core.database import get_db
from app.models.user import UserRecord
from app.repositories.scenario_repo import ScenarioRepository
from app.schemas.cir import CIRSpecification
from app.services.stix_interop import STIXInteropError, STIXInteropService

router = APIRouter(prefix="/api/stix", tags=["STIX"])
interop = STIXInteropService()


@router.post("/import")
def import_stix(
    bundle: dict,
    db: Session = Depends(get_db),
    current_user: UserRecord = Depends(get_current_user),
):
    try:
        cir = interop.import_bundle(bundle, scenario_id=bundle.get("id", "stix-import"))
    except STIXInteropError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error
    record = ScenarioRepository(db).save_scenario(
        original_input="STIX 2.1 import",
        cir_graph_data=cir.model_dump(mode="json"),
        owner_id=current_user.id,
    )
    return {"id": str(record.id), "cir": cir}


@router.get("/export/{scenario_id}")
def export_stix(cir: CIRSpecification = Depends(get_owned_cir)):
    return interop.export_bundle(cir)
