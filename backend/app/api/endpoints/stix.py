from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.repositories.scenario_repo import ScenarioRepository
from app.services.stix_interop import STIXInteropError, STIXInteropService

router = APIRouter(prefix="/api/stix", tags=["STIX"])
interop = STIXInteropService()


@router.post("/import")
def import_stix(bundle: dict, db: Session = Depends(get_db)):
    try:
        cir = interop.import_bundle(bundle, scenario_id=bundle.get("id", "stix-import"))
        record = ScenarioRepository(db).save_scenario(
            original_input="STIX 2.1 import",
            cir_graph_data=cir.model_dump(mode="json"),
        )
        return {"id": str(record.id), "cir": cir}
    except STIXInteropError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error


@router.get("/export/{scenario_id}")
def export_stix(scenario_id: str, db: Session = Depends(get_db)):
    cir = ScenarioRepository(db).get_cir(scenario_id)
    if cir is None:
        raise HTTPException(status_code=404, detail="Scenario not found")
    return interop.export_bundle(cir)