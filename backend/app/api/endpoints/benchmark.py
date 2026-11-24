import json
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException
from app.api.deps import get_owned_cir
from app.schemas.cir import CIRSpecification
from app.services.coverage_analyzer import CoverageAnalyzer

router = APIRouter(prefix="/benchmark", tags=["Benchmark"])


@router.get("/report/summary")
def benchmark_report():
    report_path = Path(__file__).resolve().parents[4] / "benchmark" / "results" / "report.json"
    if not report_path.exists():
        raise HTTPException(status_code=404, detail="Benchmark report not found")
    return json.loads(report_path.read_text(encoding="utf-8"))


@router.get("/{scenario_id}")
def benchmark_scenario(scenario_id: str, cir: CIRSpecification = Depends(get_owned_cir)):
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
