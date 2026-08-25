from itertools import combinations
from typing import Any

from app.schemas.simulation import BudgetControl, BudgetOptimizationResult


class BudgetOptimizer:
    """Selects explicitly supplied controls under a security budget."""

    def greedy(
        self,
        controls: list[BudgetControl],
        security_budget: float,
        **context: Any,
    ) -> BudgetOptimizationResult:
        ranked = sorted(
            controls,
            key=lambda control: (
                -(control.expected_risk_reduction / control.implementation_cost)
                if control.implementation_cost
                else float("-inf"),
                control.implementation_cost,
                control.control_id,
            ),
        )
        selected = []
        remaining = security_budget
        for control in ranked:
            if control.implementation_cost <= remaining:
                selected.append(control)
                remaining -= control.implementation_cost
        return self._result(selected, "greedy", **context)

    def exact(
        self,
        controls: list[BudgetControl],
        security_budget: float,
        **context: Any,
    ) -> BudgetOptimizationResult:
        best: tuple[float, float, tuple[str, ...], list[BudgetControl]] = (
            -1,
            float("inf"),
            (),
            [],
        )
        for size in range(len(controls) + 1):
            for selection in combinations(controls, size):
                cost = sum(control.implementation_cost for control in selection)
                if cost > security_budget + 1e-9:
                    continue
                reduction = sum(
                    control.expected_risk_reduction for control in selection
                )
                ids = tuple(sorted(control.control_id for control in selection))
                candidate = (reduction, cost, ids, list(selection))
                if candidate[0] > best[0] or (
                    candidate[0] == best[0]
                    and (candidate[1], candidate[2]) < (best[1], best[2])
                ):
                    best = candidate
        return self._result(best[3], "exact", **context)

    def optimize(
        self,
        controls: list[BudgetControl],
        security_budget: float,
        *,
        algorithm: str = "exact",
        **context: Any,
    ) -> BudgetOptimizationResult:
        if algorithm == "greedy":
            return self.greedy(controls, security_budget, **context)
        if algorithm == "exact":
            return self.exact(controls, security_budget, **context)
        raise ValueError("algorithm must be 'greedy' or 'exact'")

    def _result(
        self,
        selected: list[BudgetControl],
        algorithm: str,
        *,
        baseline_risk: float = 0.0,
        attack_paths: list[list[str]] | None = None,
        critical_paths: list[list[str]] | None = None,
        node_techniques: dict[str, str] | None = None,
    ) -> BudgetOptimizationResult:
        total_cost = sum(control.implementation_cost for control in selected)
        reduction = sum(control.expected_risk_reduction for control in selected)
        covered_techniques = {
            technique
            for control in selected
            for technique in control.affected_techniques
        }
        node_techniques = node_techniques or {}

        def disrupted(path: list[str]) -> bool:
            return bool(
                {node_techniques.get(node_id, "") for node_id in path}
                & covered_techniques
            )

        paths = attack_paths or []
        critical = critical_paths or []
        disrupted_paths = [path for path in paths if disrupted(path)]
        residual_critical = [path for path in critical if not disrupted(path)]
        improvement = reduction / baseline_risk * 100 if baseline_risk > 0 else 0.0
        return BudgetOptimizationResult(
            recommended_controls=selected,
            total_cost=round(total_cost, 2),
            expected_risk_reduction=round(reduction, 2),
            rw_apds_improvement=round(min(100.0, max(0.0, improvement)), 2),
            attack_paths_disrupted=disrupted_paths,
            residual_critical_paths=residual_critical,
            algorithm=algorithm,
        )