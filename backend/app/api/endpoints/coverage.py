from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.repositories.scenario_repo import ScenarioRepository
from app.services.coverage_analyzer import CoverageAnalyzer

router = APIRouter(prefix="/coverage")


@router.get("/{scenario_id}")
async def get_coverage(scenario_id: str, db: Session = Depends(get_db)):
    repo = ScenarioRepository(db)

    cir = repo.get_cir(scenario_id)

    if cir is None:
        raise HTTPException(status_code=404, detail="Scenario not found")

    analyzer = CoverageAnalyzer(cir)

    return analyzer.analyze()
