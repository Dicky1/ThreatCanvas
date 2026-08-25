from app.services.graph_analysis_engine import GraphAnalysisEngine


def test_graph_analysis_explains_missing_detection_and_probability():
    cir = {
        "attack_graph": {
            "nodes": [
                {
                    "step_id": "step1",
                    "tactic": "initial-access",
                    "technique": "T1566.001",
                    "target": "email client",
                    "action_type": "Email Delivery",
                    "probability": 0.8,
                    "impact": 0.4,
                    "evidence": [],
                },
                {
                    "step_id": "step2",
                    "tactic": "execution",
                    "technique": "T1059.001",
                    "target": "production database",
                    "action_type": "Execution",
                    "probability": 0.5,
                    "impact": 1.0,
                    "crown_jewel_exposure": 1.0,
                    "trust_boundary_crossings": 0.8,
                    "evidence": [],
                },
            ],
            "edges": [{"from": "step1", "to": "step2", "relationship": "LEADS_TO"}],
        }
    }

    result = GraphAnalysisEngine(cir).analyze()

    assert result.critical_path_explanation.criticality_score > 0
    assert result.missing_detection_details[0].node_id == "step1"
    assert result.most_likely_path is not None
    assert result.most_likely_path.probability == 0.4
    assert result.trust_boundary_signals[0].severity == "High"
    assert result.asset_risk_signals[1].asset == "production database"
