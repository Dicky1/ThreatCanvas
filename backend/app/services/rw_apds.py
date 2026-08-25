import json
import os
from dataclasses import asdict, dataclass
from typing import Any

FACTORS = (
    "technique_criticality",
    "asset_criticality",
    "attack_path_criticality",
    "reachability",
    "impact",
    "probability",
    "trust_boundary_crossings",
    "crown_jewel_exposure",
)


@dataclass(frozen=True)
class RWAPDSWeights:
    technique_criticality: float = 1.0
    asset_criticality: float = 1.0
    attack_path_criticality: float = 1.0
    reachability: float = 1.0
    impact: float = 1.0
    probability: float = 1.0
    trust_boundary_crossings: float = 1.0
    crown_jewel_exposure: float = 1.0

    @classmethod
    def from_environment(cls) -> "RWAPDSWeights":
        raw = os.getenv("RW_APDS_WEIGHTS_JSON")
        if not raw:
            return cls()
        values = json.loads(raw)
        unknown = set(values) - set(FACTORS)
        if unknown:
            raise ValueError(f"Unknown RW-APDS weights: {sorted(unknown)}")
        if any(float(value) < 0 for value in values.values()):
            raise ValueError("RW-APDS weights cannot be negative")
        return cls(**{key: float(value) for key, value in values.items()})

    def normalized(self) -> dict[str, float]:
        values = asdict(self)
        total = sum(values.values())
        if total <= 0:
            raise ValueError("At least one RW-APDS weight must be positive")
        return {key: value / total for key, value in values.items()}


class RWAPDSCalculator:
    def __init__(self, weights: RWAPDSWeights | None = None):
        self.weights = weights or RWAPDSWeights.from_environment()

    def _node_risk(self, node: Any) -> float:
        normalized = self.weights.normalized()
        return 100 * sum(
            weight * float(getattr(node, factor, 0.0))
            for factor, weight in normalized.items()
        )

    def score(
        self,
        baseline_nodes: list[Any],
        residual_nodes: list[Any],
        baseline_paths: list[list[str]],
        residual_paths: list[list[str]],
        critical_paths: list[list[str]],
    ) -> dict[str, Any]:
        residual_ids = {self._node_id(node) for node in residual_nodes}
        baseline_risk = sum(self._node_risk(node) for node in baseline_nodes)
        residual_risk = sum(
            self._node_risk(node)
            for node in baseline_nodes
            if self._node_id(node) in residual_ids
        )
        residual_path_keys = {tuple(path) for path in residual_paths}
        eliminated_paths = [
            path for path in baseline_paths if tuple(path) not in residual_path_keys
        ]
        eliminated_critical_paths = [
            path for path in critical_paths if tuple(path) not in residual_path_keys
        ]
        disruption = (
            ((baseline_risk - residual_risk) / (100 * len(baseline_nodes))) * 100
            if baseline_nodes
            else 0.0
        )
        return {
            "baseline_risk": round(baseline_risk, 2),
            "residual_risk": round(residual_risk, 2),
            "attack_paths_eliminated": eliminated_paths,
            "critical_paths_eliminated": eliminated_critical_paths,
            "weighted_node_disruption": round(disruption, 2),
            "score": round(max(0.0, min(100.0, disruption)), 2),
            "weights": self.weights.normalized(),
        }

    @staticmethod
    def _node_id(node: Any) -> str:
        return str(getattr(node, "step_id", getattr(node, "id", "")))