from app.schemas.simulation import BudgetControl
from app.services.budget_optimizer import BudgetOptimizer


def controls():
    return [
        BudgetControl(
            control_id="a",
            control_name="Broad control",
            implementation_cost=6,
            affected_techniques=["T1"],
            expected_risk_reduction=12,
        ),
        BudgetControl(
            control_id="b",
            control_name="Efficient control",
            implementation_cost=4,
            affected_techniques=["T2"],
            expected_risk_reduction=8,
        ),
        BudgetControl(
            control_id="c",
            control_name="Best combination",
            implementation_cost=5,
            affected_techniques=["T3"],
            expected_risk_reduction=10,
        ),
    ]


def test_exact_optimizer_beats_greedy_with_same_budget():
    optimizer = BudgetOptimizer()
    greedy = optimizer.greedy(controls(), 10, baseline_risk=100)
    exact = optimizer.exact(controls(), 10, baseline_risk=100)

    assert [control.control_id for control in greedy.recommended_controls] == ["b", "c"]
    assert [control.control_id for control in exact.recommended_controls] == ["a", "b"]
    assert greedy.total_cost <= 10
    assert exact.total_cost == 10
    assert exact.expected_risk_reduction > greedy.expected_risk_reduction


def test_optimizer_reports_paths_and_residual_critical_paths():
    result = BudgetOptimizer().exact(
        controls()[:1],
        10,
        baseline_risk=100,
        attack_paths=[["n1", "n2"], ["n3"]],
        critical_paths=[["n1", "n2"], ["n3"]],
        node_techniques={"n1": "T1", "n2": "T2", "n3": "T9"},
    )

    assert result.attack_paths_disrupted == [["n1", "n2"]]
    assert result.residual_critical_paths == [["n3"]]
    assert result.rw_apds_improvement == 12.0