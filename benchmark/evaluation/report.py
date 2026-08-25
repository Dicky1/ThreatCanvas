from __future__ import annotations

import argparse
import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class ClassificationMetrics:
    precision: float
    recall: float
    f1: float
    true_positive: int
    false_positive: int
    false_negative: int


@dataclass(frozen=True)
class ScenarioEvaluation:
    scenario_id: str
    cir_schema_valid: bool
    attack_precision: float
    attack_recall: float
    attack_f1: float
    tactic_recall: float
    graph_ordering_accuracy: float
    expected_techniques: list[str]
    predicted_techniques: list[str]
    missing_techniques: list[str]
    extra_techniques: list[str]


def _load_json(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as stream:
        return json.load(stream)


def _attack_graph(payload: dict[str, Any]) -> dict[str, Any]:
    if "cir" in payload:
        payload = payload["cir"]
    return payload.get("attack_graph", payload)


def _nodes(payload: dict[str, Any]) -> list[dict[str, Any]]:
    graph = _attack_graph(payload)
    nodes = graph.get("nodes", [])
    return [node for node in nodes if isinstance(node, dict)]


def _edges(payload: dict[str, Any]) -> list[dict[str, Any]]:
    graph = _attack_graph(payload)
    edges = graph.get("edges", [])
    return [edge for edge in edges if isinstance(edge, dict)]


def _techniques(payload: dict[str, Any]) -> list[str]:
    return [
        str(node.get("technique", "")).upper()
        for node in _nodes(payload)
        if node.get("technique")
    ]


def _tactics(payload: dict[str, Any]) -> set[str]:
    return {
        str(node.get("tactic", "")).lower()
        for node in _nodes(payload)
        if node.get("tactic")
    }


def _schema_valid(payload: dict[str, Any]) -> bool:
    nodes = _nodes(payload)
    edges = _edges(payload)
    node_ids = {str(node.get("step_id", "")) for node in nodes if node.get("step_id")}
    if not nodes or not node_ids:
        return False
    required_node_fields = {"step_id", "tactic", "technique", "target", "action_type"}
    if any(required_node_fields - set(node) for node in nodes):
        return False
    for edge in edges:
        source = str(edge.get("from") or edge.get("source") or "")
        target = str(edge.get("to") or edge.get("target") or "")
        if source not in node_ids or target not in node_ids:
            return False
    return True


def classification(expected: set[str], predicted: set[str]) -> ClassificationMetrics:
    tp = len(expected & predicted)
    fp = len(predicted - expected)
    fn = len(expected - predicted)
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return ClassificationMetrics(
        precision=round(precision * 100, 2),
        recall=round(recall * 100, 2),
        f1=round(f1 * 100, 2),
        true_positive=tp,
        false_positive=fp,
        false_negative=fn,
    )


def ordering_accuracy(expected_order: list[str], predicted_order: list[str]) -> float:
    if len(expected_order) < 2:
        return 100.0
    expected_pairs = {
        (expected_order[index], expected_order[index + 1])
        for index in range(len(expected_order) - 1)
    }
    predicted_pairs = {
        (predicted_order[index], predicted_order[index + 1])
        for index in range(len(predicted_order) - 1)
    }
    if not expected_pairs:
        return 100.0
    return round(len(expected_pairs & predicted_pairs) / len(expected_pairs) * 100, 2)


def evaluate_scenario(cir_payload: dict[str, Any], ground_truth: dict[str, Any]) -> ScenarioEvaluation:
    expected_techniques = [technique.upper() for technique in ground_truth["expected_techniques"]]
    predicted_techniques = _techniques(cir_payload)
    attack_metrics = classification(set(expected_techniques), set(predicted_techniques))

    expected_tactics = {str(tactic).lower() for tactic in ground_truth.get("expected_tactics", [])}
    predicted_tactics = _tactics(cir_payload)
    tactic_recall = (
        round(len(expected_tactics & predicted_tactics) / len(expected_tactics) * 100, 2)
        if expected_tactics
        else 100.0
    )

    return ScenarioEvaluation(
        scenario_id=str(ground_truth["scenario_id"]),
        cir_schema_valid=_schema_valid(cir_payload),
        attack_precision=attack_metrics.precision,
        attack_recall=attack_metrics.recall,
        attack_f1=attack_metrics.f1,
        tactic_recall=tactic_recall,
        graph_ordering_accuracy=ordering_accuracy(
            [technique.upper() for technique in ground_truth.get("expected_order", [])],
            predicted_techniques,
        ),
        expected_techniques=expected_techniques,
        predicted_techniques=predicted_techniques,
        missing_techniques=sorted(set(expected_techniques) - set(predicted_techniques)),
        extra_techniques=sorted(set(predicted_techniques) - set(expected_techniques)),
    )


def aggregate(results: list[ScenarioEvaluation]) -> dict[str, Any]:
    count = len(results)
    if count == 0:
        return {"scenario_count": 0}
    return {
        "scenario_count": count,
        "cir_validity_rate": round(sum(item.cir_schema_valid for item in results) / count * 100, 2),
        "attack_precision": round(sum(item.attack_precision for item in results) / count, 2),
        "attack_recall": round(sum(item.attack_recall for item in results) / count, 2),
        "attack_f1": round(sum(item.attack_f1 for item in results) / count, 2),
        "tactic_recall": round(sum(item.tactic_recall for item in results) / count, 2),
        "graph_ordering_accuracy": round(sum(item.graph_ordering_accuracy for item in results) / count, 2),
    }


def evaluate_directory(cir_dir: Path, ground_truth_dir: Path) -> dict[str, Any]:
    results = []
    for truth_path in sorted(ground_truth_dir.glob("*.json")):
        truth = _load_json(truth_path)
        scenario_id = truth["scenario_id"]
        cir_path = cir_dir / f"{scenario_id}.json"
        if not cir_path.exists():
            continue
        results.append(evaluate_scenario(_load_json(cir_path), truth))
    return {
        "summary": aggregate(results),
        "scenarios": [asdict(result) for result in results],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate ThreatCanvas CIR outputs against benchmark ground truth.")
    parser.add_argument("--cir-dir", required=True, type=Path, help="Directory containing CIR JSON files named <scenario_id>.json")
    parser.add_argument("--ground-truth-dir", default=Path("benchmark/ground_truth"), type=Path)
    parser.add_argument("--output", type=Path, help="Optional JSON report path")
    args = parser.parse_args()

    report = evaluate_directory(args.cir_dir, args.ground_truth_dir)
    rendered = json.dumps(report, indent=2)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered + "\n", encoding="utf-8")
    print(rendered)


if __name__ == "__main__":
    main()
