"""Model benchmark: run the bundled narratives through the CIR pipeline with
one or more LLM profiles and score the output against ground truth."""

from __future__ import annotations

import json
import time
from collections.abc import Awaitable, Callable
from functools import lru_cache
from pathlib import Path
from typing import Any

from app.schemas.cir import CIRSpecification
from app.services.attack_knowledge import ATTACKKnowledgeService
from app.services.cir_pipeline import PipelineValidationError, generate_cir
from app.services.llm_parser import LLMUnavailableError

CASES_PATH = Path(__file__).parents[1] / "data" / "benchmark" / "cases.json"


@lru_cache(maxsize=1)
def load_cases() -> list[dict[str, Any]]:
    with CASES_PATH.open(encoding="utf-8") as stream:
        return json.load(stream)["cases"]


def _prf(expected: set[str], predicted: set[str]) -> dict[str, float]:
    tp = len(expected & predicted)
    precision = tp / len(predicted) if predicted else 0.0
    recall = tp / len(expected) if expected else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {"precision": round(precision, 4), "recall": round(recall, 4), "f1": round(f1, 4)}


def ordering_accuracy(expected_order: list[str], predicted: list[str]) -> float:
    """Share of consecutive expected pairs that appear in the same relative
    order in the prediction (missing techniques count as misses)."""
    if len(expected_order) < 2:
        return 1.0
    position = {}
    for index, technique in enumerate(predicted):
        position.setdefault(technique, index)
    pairs = list(zip(expected_order, expected_order[1:], strict=False))
    good = sum(1 for a, b in pairs if a in position and b in position and position[a] < position[b])
    return round(good / len(pairs), 4)


def score(case: dict[str, Any], cir: CIRSpecification | None) -> dict[str, Any]:
    expected = [t.upper() for t in case["expected_techniques"]]
    predicted = [str(n.technique).upper() for n in cir.attack_graph.nodes] if cir else []
    exact = _prf(set(expected), set(predicted))
    parent = _prf({t.split(".")[0] for t in expected}, {t.split(".")[0] for t in predicted})
    return {
        "exact": exact,
        "parent": parent,
        "ordering": ordering_accuracy([t.upper() for t in case["expected_order"]], predicted) if cir else 0.0,
        "predicted": predicted,
        "missing": sorted(set(expected) - set(predicted)),
        "extra": sorted(set(predicted) - set(expected)),
        "nodes": len(predicted),
    }


Generator = Callable[..., Awaitable[CIRSpecification]]


async def run_case(case: dict[str, Any], generator: Generator, knowledge: ATTACKKnowledgeService) -> dict[str, Any]:
    started = time.monotonic()
    result: dict[str, Any] = {"case_id": case["id"], "title": case["title"]}
    try:
        outcome = await generate_cir(case["narrative"], generator, knowledge)
        result.update(status="valid", repair_attempts=len(outcome.attempts), **score(case, outcome.cir))
    except PipelineValidationError as error:
        result.update(status="invalid", repair_attempts=len(error.attempts), **score(case, None),
                      error=(error.validation.get("errors") or ["validation failed"])[0][:300])
    except LLMUnavailableError:
        result.update(status="llm_error", repair_attempts=0, **score(case, None), error="LLM provider request failed")
    except Exception as error:  # noqa: BLE001 - a benchmark keeps going on unexpected model output
        result.update(status="error", repair_attempts=0, **score(case, None), error=type(error).__name__)
    result["latency_ms"] = round((time.monotonic() - started) * 1000)
    return result


def summarize(results: list[dict[str, Any]]) -> dict[str, Any]:
    if not results:
        return {}
    count = len(results)

    def mean(values: list[float]) -> float:
        return round(sum(values) / len(values), 4) if values else 0.0

    return {
        "cases": count,
        "valid_rate": round(sum(r["status"] == "valid" for r in results) / count, 4),
        "exact_f1": mean([r["exact"]["f1"] for r in results]),
        "exact_precision": mean([r["exact"]["precision"] for r in results]),
        "exact_recall": mean([r["exact"]["recall"] for r in results]),
        "parent_f1": mean([r["parent"]["f1"] for r in results]),
        "ordering": mean([r["ordering"] for r in results]),
        "avg_repair_attempts": mean([r["repair_attempts"] for r in results]),
        "avg_latency_ms": round(mean([r["latency_ms"] for r in results])),
        "errors": sum(r["status"] in ("llm_error", "error") for r in results),
    }


async def run_benchmark(
    profile_names: list[str],
    case_ids: list[str] | None,
    generator_for: Callable[[str], Generator],
    knowledge: ATTACKKnowledgeService,
    on_progress: Callable[[dict[str, Any]], None] | None = None,
) -> dict[str, Any]:
    cases = [c for c in load_cases() if not case_ids or c["id"] in case_ids]
    report: dict[str, Any] = {"profiles": {}, "cases": [c["id"] for c in cases]}
    for name in profile_names:
        generator = generator_for(name)
        results = []
        for case in cases:
            results.append(await run_case(case, generator, knowledge))
            report["profiles"][name] = {"summary": summarize(results), "results": results}
            if on_progress:
                on_progress(report)
    return report
