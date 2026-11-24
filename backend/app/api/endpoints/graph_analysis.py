from fastapi import APIRouter, Depends, HTTPException

from app.api.deps import get_owned_scenario
from app.models.scenario import ScenarioRecord
from app.schemas.graph_analysis import AttackGraphAnalysis
from app.services.graph_analysis_engine import GraphAnalysisEngine

router = APIRouter()


@router.get("/graph-analysis/{scenario_id}", response_model=AttackGraphAnalysis)
def analyze_graph(scenario: ScenarioRecord = Depends(get_owned_scenario)):
    if not scenario.cir_graph_data:
        raise HTTPException(status_code=400, detail="CIR Graph Data not found for this scenario")

    analysis_result = GraphAnalysisEngine(scenario.cir_graph_data).analyze()
    if not analysis_result:
        raise HTTPException(status_code=400, detail="Analysis failed")
    return analysis_result
