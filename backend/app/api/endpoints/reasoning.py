from fastapi import APIRouter, HTTPException, Depends
from sqlalchemy.orm import Session
from app.core.database import get_db 
from app.models.scenario import ScenarioRecord
from app.schemas.threat_reasoning import ThreatReasoning
from app.schemas.cir import CIRSpecification
from app.services.threat_reasoning_engine import ThreatReasoningEngine
from app.services.graph_analysis_engine import GraphAnalysisEngine

router = APIRouter()
reasoning_engine = ThreatReasoningEngine()
# HAPUS BARIS INI: graph_engine = GraphAnalysisEngine() 
# (Karena harus diinisialisasi dengan data CIR di dalam fungsi)

@router.get("/reasoning/{scenario_id}", response_model=ThreatReasoning)
def get_threat_reasoning(scenario_id: str, db: Session = Depends(get_db)):
    try:
        # 1. Ambil data scenario dari database
        scenario = db.query(ScenarioRecord).filter(ScenarioRecord.id == scenario_id).first()
        if not scenario:
            raise HTTPException(status_code=404, detail="Scenario not found")

        # 2. Validasi ketersediaan CIR Data
        if not scenario.cir_graph_data:
            raise HTTPException(status_code=400, detail="CIR data is empty for this scenario. Please run parser first.")
        
        # 3. Parsing tipe data CIR
        cir_dict = scenario.cir_graph_data
        
        # Jika cir_graph_data di database masih berupa dict, ubah ke skema Pydantic
        if isinstance(cir_dict, dict):
            cir_spec = CIRSpecification(**cir_dict)
        else:
            cir_spec = cir_dict

        # 4. Inisialisasi Graph Engine dengan CIR Specification
        # PINDAHKAN KE SINI
        graph_engine = GraphAnalysisEngine(cir_specification=cir_spec) 

        # 5. Generate Graph Analysis untuk mendapatkan data coverage
        # Catatan: Jika method analyze() di arsitektur Anda butuh parameter, 
        # ubah menjadi graph_engine.analyze(cir_spec)
        graph_data = graph_engine.analyze() 

        # 6. Lempar kedua data ke Reasoning Engine
        result = reasoning_engine.generate_reasoning(cir=cir_spec, graph_analysis=graph_data)
        
        return result
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))