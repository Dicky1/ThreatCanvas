from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.api.deps import get_current_user
from app.repositories.scenario_repo import ScenarioRepository
from app.models.user import UserRecord
from app.services.d3fend_mapping import D3FENDMappingService

router = APIRouter(prefix="/d3fend", tags=["D3FEND"])

@router.get("/{scenario_id}")
def get_d3fend_remediation(
    scenario_id: str,
    db: Session = Depends(get_db),
    current_user: UserRecord = Depends(get_current_user)
):
    """
    Otomatisasi Remediasi (D3FEND Copilot).
    Mengekstrak teknik MITRE ATT&CK dari skenario aktif dan 
    memetakan kontrol pertahanan D3FEND yang relevan.
    """
    repo = ScenarioRepository(db)
    scenario = repo.get_scenario(scenario_id, current_user.id)
    if not scenario:
        raise HTTPException(status_code=404, detail="Skenario tidak ditemukan")

    cir_data = scenario.cir_graph_data
    if not cir_data or "attack_graph" not in cir_data or "nodes" not in cir_data["attack_graph"]:
        return {"remediations": []}

    d3fend_service = D3FENDMappingService()
    
    unique_techs = {}
    nodes = cir_data["attack_graph"]["nodes"]
    for node in nodes:
        tech = node.get("technique")
        if tech and tech.startswith("T"):
            if tech not in unique_techs:
                unique_techs[tech] = node.get("technique_name", "")

    remediations = []
    for tech_id, tech_name in unique_techs.items():
        mappings = d3fend_service.lookup(tech_id)
        # Convert D3FENDMapping dataclass to dict
        countermeasures = [
            {
                "defensive_technique": m.defensive_technique,
                "rationale": m.rationale,
                "source": m.source,
                "confidence": m.confidence
            }
            for m in mappings
        ]
        
        remediations.append({
            "technique_id": tech_id,
            "technique_name": tech_name,
            "countermeasures": countermeasures
        })

    return {"remediations": remediations}
