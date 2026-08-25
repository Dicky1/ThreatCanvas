from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.repositories.scenario_repo import ScenarioRepository
from app.schemas.cti import AttackTimeline
from app.services.attack_timeline import AttackTimelineService

router = APIRouter(prefix="/timeline", tags=["Timeline"])


@router.get("/{scenario_id}", response_model=AttackTimeline)
def get_timeline(scenario_id: str, db: Session = Depends(get_db)):
    cir = ScenarioRepository(db).get_cir(scenario_id)
    if cir is None:
        raise HTTPException(status_code=404, detail="Scenario not found")
    return AttackTimelineService().build(scenario_id, cir)
