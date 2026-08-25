from app.schemas.cir import CIRNode
from app.services.d3fend_mapping import D3FENDMappingService
from app.services.defense_optimization_engine import DefenseOptimizationEngine
from app.services.threat_reasoning_engine import ThreatReasoningEngine


def test_d3fend_service_returns_only_explicit_mappings():
    service = D3FENDMappingService(
        mappings=[
            {
                "attack_technique": "T1059.001",
                "defensive_technique": "D3-PSEP",
                "rationale": "Restrict script execution",
                "source": "D3FEND authoritative mapping",
                "confidence": 0.95,
            }
        ]
    )

    assert service.lookup("T1059.001")[0].defensive_technique == "D3-PSEP"
    assert service.lookup("T1486") == ()


def test_d3fend_recommendation_contains_graph_impact():
    engine = DefenseOptimizationEngine(
        ThreatReasoningEngine(),
        D3FENDMappingService(
            mappings=[
                {
                    "attack_technique": "T1059.001",
                    "defensive_technique": "D3-PSEP",
                    "rationale": "Restrict script execution",
                    "source": "D3FEND authoritative mapping",
                    "confidence": 0.95,
                }
            ]
        ),
    )
    nodes = [
        CIRNode(
            step_id="step-1",
            tactic="TA0002",
            technique="T1059.001",
            target="host-1",
            action_type="PowerShell",
            evidence=[{"description": "command"}],
        )
    ]

    recommendations = engine.generate_optimization(
        original_nodes=nodes,
        simulated_nodes=[],
        total_risk_score=10,
        attack_paths=[["step-1"]],
    )

    recommendation = next(item for item in recommendations if item.defensive_technique == "D3-PSEP")
    assert recommendation.affected_attack_nodes == ["step-1"]
    assert recommendation.affected_attack_paths == [["step-1"]]
    assert recommendation.source == "D3FEND authoritative mapping"
    assert recommendation.confidence == 0.95