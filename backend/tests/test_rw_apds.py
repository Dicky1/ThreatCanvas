from app.schemas.cir import CIRNode
from app.services.rw_apds import RWAPDSCalculator, RWAPDSWeights


def node(step_id, **values):
    return CIRNode(
        step_id=step_id,
        tactic="TA0002",
        technique="T1059.001",
        target="host-1",
        action_type="Execution",
        evidence=[{"description": "observed"}],
        **values,
    )


def test_high_risk_disruption_scores_higher_than_low_risk_disruption():
    high = node(
        "high",
        technique_criticality=1,
        asset_criticality=1,
        impact=1,
        probability=1,
        crown_jewel_exposure=1,
    )
    low = node(
        "low",
        technique_criticality=0.1,
        asset_criticality=0.1,
        impact=0.1,
        probability=0.1,
    )
    weights = RWAPDSWeights(
        technique_criticality=1,
        asset_criticality=1,
        impact=1,
        probability=1,
        crown_jewel_exposure=1,
        attack_path_criticality=0,
        reachability=0,
        trust_boundary_crossings=0,
    )
    calculator = RWAPDSCalculator(weights)

    high_result = calculator.score([high], [], [["high"]], [], [["high"]])
    low_result = calculator.score([low], [], [["low"]], [], [["low"]])

    assert high_result["score"] > low_result["score"]
    assert high_result["baseline_risk"] > low_result["baseline_risk"]
    assert high_result["critical_paths_eliminated"] == [["high"]]


def test_weights_are_normalized_and_configurable():
    weights = RWAPDSWeights(
        technique_criticality=3,
        asset_criticality=0,
        attack_path_criticality=0,
        reachability=0,
        impact=1,
        probability=0,
        trust_boundary_crossings=0,
        crown_jewel_exposure=0,
    )
    result = RWAPDSCalculator(weights).score(
        [node("n", technique_criticality=1, impact=0)], [], [], [], []
    )

    assert result["weights"]["technique_criticality"] == 0.75
    assert result["score"] == 75.0