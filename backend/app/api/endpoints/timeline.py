from fastapi import APIRouter, Depends

from app.api.deps import get_owned_cir
from app.schemas.cir import CIRSpecification
from app.schemas.cti import AttackTimeline
from app.services.attack_timeline import AttackTimelineService

router = APIRouter(prefix="/timeline", tags=["Timeline"])


@router.get("/{scenario_id}", response_model=AttackTimeline)
def get_timeline(scenario_id: str, cir: CIRSpecification = Depends(get_owned_cir)):
    return AttackTimelineService().build(scenario_id, cir)
