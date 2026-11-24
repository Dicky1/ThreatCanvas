from fastapi import APIRouter, Depends

from app.api.deps import get_owned_scenario
from app.models.scenario import ScenarioRecord
from app.services.d3fend_mapping import D3FENDMappingService

router = APIRouter(prefix="/d3fend", tags=["D3FEND"])

@router.get("/{scenario_id}")
def get_d3fend_remediation(
    scenario_id: str,
    scenario: ScenarioRecord = Depends(get_owned_scenario),
):
    """
    Otomatisasi Remediasi (D3FEND Copilot).
    Mengekstrak teknik MITRE ATT&CK dari skenario aktif dan 
    memetakan kontrol pertahanan D3FEND yang relevan.
    """

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
