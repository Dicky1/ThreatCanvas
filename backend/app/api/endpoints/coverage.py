from fastapi import APIRouter, Depends

from app.api.deps import get_owned_cir
from app.schemas.cir import CIRSpecification
from app.services.coverage_analyzer import CoverageAnalyzer

router = APIRouter(prefix="/coverage")


@router.get("/{scenario_id}")
async def get_coverage(cir: CIRSpecification = Depends(get_owned_cir)):
    return CoverageAnalyzer(cir).analyze()
