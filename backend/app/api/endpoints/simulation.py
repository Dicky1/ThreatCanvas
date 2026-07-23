from fastapi import APIRouter, HTTPException, Depends
from typing import Any, List, Optional, Dict
from sqlalchemy.orm import Session
from app.core.database import get_db

from app.models.scenario import ScenarioRecord
from app.schemas.simulation import SimulationRequest, SimulationResult
from app.schemas.cir import CIRSpecification
from app.services.attack_simulation_engine import AttackSimulationEngine
from app.services.defense_optimization_engine import DefenseOptimizationEngine
from app.services.threat_reasoning_engine import ThreatReasoningEngine

# Inisialisasi router FastAPI
router = APIRouter()


def get_optimization_engine() -> DefenseOptimizationEngine:
    threat_engine = ThreatReasoningEngine()
    return DefenseOptimizationEngine(threat_engine)


@router.post("/{scenario_id}", response_model=SimulationResult)
async def run_attack_simulation(
    scenario_id: str,
    request: SimulationRequest,
    db: Session = Depends(get_db),
    opt_engine: DefenseOptimizationEngine = Depends(get_optimization_engine),
):
    """
    Menjalankan What-If Analysis dengan memotong teknik yang diblokir dari Attack Graph
    dan mengkalkulasi ulang seluruh metrik secara deterministik.
    """

    # 1. Ambil data scenario dari DB
    scenario = db.query(ScenarioRecord).filter(ScenarioRecord.id == scenario_id).first()

    if not scenario:
        raise HTTPException(status_code=404, detail="Scenario not found")

    if not scenario.cir_graph_data:
        raise HTTPException(
            status_code=400, detail="CIR Graph Data not found for this scenario"
        )

    # 2. Parse data JSON dari DB menjadi Pydantic Object (CIRSpecification)
    try:
        if isinstance(scenario.cir_graph_data, dict):
            if "cir" in scenario.cir_graph_data:
                original_cir = CIRSpecification(**scenario.cir_graph_data["cir"])
            else:
                original_cir = CIRSpecification(**scenario.cir_graph_data)
        else:
            original_cir = scenario.cir_graph_data

    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Gagal mem-parsing data CIR dari Database: {str(e)}",
        )

    try:
        # 3. Jalankan simulasi menggunakan Engine
        sim_engine = AttackSimulationEngine()
        sim_result = sim_engine.run_simulation(
            original_cir=original_cir, blocked_techniques=request.blocked_techniques
        )

        # 4. Filter node untuk DefenseOptimizationEngine
        original_nodes = getattr(original_cir.attack_graph, "nodes", [])
        remaining_node_ids = set(getattr(sim_result, "remaining_nodes", []))
        
        simulated_nodes = [
            node for node in original_nodes 
            if getattr(node, "step_id", getattr(node, "id", None)) in remaining_node_ids
        ]

        total_base_score = sim_result.metrics_before.risk_score

        # 5. Jalankan optimasi kontrol pertahanan
        optimized_controls = opt_engine.generate_optimization(
            original_nodes=original_nodes,
            simulated_nodes=simulated_nodes,
            total_risk_score=total_base_score
        )

        # 6. Pastikan format struktur data aman untuk Pydantic
        formatted_removed_nodes = []
        for n in sim_result.removed_nodes:
            if isinstance(n, dict):
                formatted_removed_nodes.append(n)
            else:
                formatted_removed_nodes.append({
                    "step_id": getattr(n, "step_id", str(n)),
                    "technique": getattr(n, "technique", "Unknown"),
                    "tactic": getattr(n, "tactic", "Unknown"),
                    "reason": getattr(n, "reason", "Blocked Technique")
                })

        formatted_removed_edges = []
        for e in sim_result.removed_edges:
            if isinstance(e, dict):
                formatted_removed_edges.append(e)
            else:
                formatted_removed_edges.append({
                    "from": getattr(e, "from", getattr(e, "source", "")),
                    "to": getattr(e, "to", getattr(e, "target", "")),
                    "relationship": getattr(e, "relationship", "leads_to")
                })

        normalized_controls = []
        if isinstance(optimized_controls, list):
            for ctrl in optimized_controls:
                if isinstance(ctrl, dict):
                    normalized_controls.append(ctrl.get("control_name", str(ctrl)))
                else:
                    normalized_controls.append(str(ctrl))

        sim_result.removed_nodes = formatted_removed_nodes
        sim_result.removed_edges = formatted_removed_edges
        sim_result.optimized_controls = normalized_controls

        return sim_result

    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Simulasi gagal dijalankan: {str(e)}"
        )