from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.repositories.scenario_repo import ScenarioRepository
from app.services.coverage_analyzer import CoverageAnalyzer

router = APIRouter(prefix="/benchmark", tags=["Benchmark"])

@router.get("/{scenario_id}")
def benchmark_scenario(scenario_id: str, db: Session = Depends(get_db)):
    cir = ScenarioRepository(db).get_cir(scenario_id)
    if cir is None:
        raise HTTPException(status_code=404, detail="Scenario not found")
    coverage = CoverageAnalyzer(cir).analyze()
    nodes = cir.attack_graph.nodes
    edges = cir.attack_graph.edges
    return {
        "scenario_id": scenario_id,
        "node_count": len(nodes),
        "edge_count": len(edges),
        "technique_count": len({node.technique for node in nodes}),
        "tactic_count": len({node.tactic for node in nodes}),
        "coverage_score": coverage.get("overall_score"),
        "covered_techniques": coverage.get("covered_techniques", []),
        "missing_techniques": coverage.get("missing_techniques", []),
    }
