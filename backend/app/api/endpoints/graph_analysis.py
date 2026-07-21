from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.models.scenario import ScenarioRecord
from app.services.graph_analysis_engine import GraphAnalysisEngine
from app.schemas.graph_analysis import AttackGraphAnalysis

router = APIRouter()


@router.get("/graph-analysis/{scenario_id}", response_model=AttackGraphAnalysis)
def analyze_graph(scenario_id: str, db: Session = Depends(get_db)):
    # Query ke database menggunakan ScenarioRecord
    scenario = db.query(ScenarioRecord).filter(ScenarioRecord.id == scenario_id).first()

    if not scenario:
        raise HTTPException(status_code=404, detail="Scenario not found")

    # Menggunakan field cir_graph_data sesuai schema database
    if not scenario.cir_graph_data:
        raise HTTPException(
            status_code=400, detail="CIR Graph Data not found for this scenario"
        )

    # Inisialisasi engine dengan data JSON graf
    engine = GraphAnalysisEngine(scenario.cir_graph_data)
    analysis_result = engine.analyze()

    if not analysis_result:
        raise HTTPException(status_code=400, detail="Analysis failed")

    return analysis_result
