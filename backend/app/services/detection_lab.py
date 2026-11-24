"""Measures Sigma rules against labelled log datasets.

Labels are per dataset ("malicious" attack recording vs "benign" baseline),
not per event, so the metrics are dataset-level:

- detected: a malicious dataset produced at least one alert from a rule
  relevant to its techniques (or any rule when either side is untagged)
- dataset recall = detected malicious datasets / malicious datasets
- benign alerts = events matched in benign datasets (false positives)
- alert precision = alerts on malicious datasets / all alerts. Attack
  recordings also contain normal activity, so this is an upper bound.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any

from app.services.sigma_eval import (
    CompiledRule,
    SigmaEvalError,
    compile_rules,
    prepare_event,
    rule_matches,
)

TIME_BUDGET_SECONDS = 30.0
MAX_SAMPLES = 3
SAMPLE_FIELDS = (
    "EventID", "Channel", "Computer", "Hostname", "UtcTime", "EventTime", "Image", "CommandLine",
    "ParentImage", "ParentCommandLine", "User", "TargetObject", "Details", "TargetFilename",
    "DestinationIp", "DestinationPort", "DestinationHostname", "QueryName", "ImageLoaded",
    "TargetImage", "SourceImage", "NewProcessName",
)


@dataclass
class LabDataset:
    id: str
    name: str
    label: str
    technique_ids: list[str]
    events: list[dict[str, Any]]


def _sample(event: dict[str, Any]) -> dict[str, Any]:
    return {key: event[key] for key in SAMPLE_FIELDS if key in event}


def _related(rule_techniques: list[str], dataset_techniques: list[str]) -> bool:
    if not rule_techniques or not dataset_techniques:
        return True
    parents = {t.split(".")[0] for t in dataset_techniques}
    return any(t in dataset_techniques or t.split(".")[0] in parents for t in rule_techniques)


def evaluate(sigma_yaml: str, datasets: list[LabDataset]) -> dict[str, Any]:
    rules, parse_errors = compile_rules(sigma_yaml)
    started = time.monotonic()
    truncated = False
    prepared = {dataset.id: [prepare_event(e) for e in dataset.events] for dataset in datasets}

    rule_reports: list[dict[str, Any]] = []
    # hits[rule_index][dataset_id] = matched event count
    hits: list[dict[str, int]] = []
    for rule in rules:
        report: dict[str, Any] = {
            "title": rule.title,
            "rule_id": rule.rule_id,
            "techniques": rule.techniques,
            "error": None,
            "malicious_hits": 0,
            "benign_hits": 0,
            "datasets": [],
        }
        rule_hits: dict[str, int] = {}
        for dataset in datasets:
            count, samples = 0, []
            try:
                for event in prepared[dataset.id]:
                    if time.monotonic() - started > TIME_BUDGET_SECONDS:
                        truncated = True
                        break
                    if rule_matches(rule, event):
                        count += 1
                        if len(samples) < MAX_SAMPLES:
                            samples.append(_sample(event))
            except SigmaEvalError as error:
                # Partial results of a rule that cannot be evaluated are discarded.
                report.update(error=str(error), malicious_hits=0, benign_hits=0, datasets=[])
                break
            rule_hits[dataset.id] = count
            report["malicious_hits" if dataset.label == "malicious" else "benign_hits"] += count
            report["datasets"].append({
                "dataset_id": dataset.id,
                "name": dataset.name,
                "label": dataset.label,
                "hits": count,
                "samples": samples,
            })
        rule_reports.append(report)
        hits.append(rule_hits if report["error"] is None else {})

    for error in parse_errors:
        rule_reports.append({
            "title": error.split(":", 1)[0], "rule_id": None, "techniques": [], "error": error,
            "malicious_hits": 0, "benign_hits": 0, "datasets": [],
        })

    malicious = [d for d in datasets if d.label == "malicious"]
    benign = [d for d in datasets if d.label == "benign"]
    dataset_results = []
    for dataset in datasets:
        relevant = [i for i, rule in enumerate(rules) if _related(rule.techniques, dataset.technique_ids)]
        alerts = sum(hits[i].get(dataset.id, 0) for i in relevant)
        dataset_results.append({
            "dataset_id": dataset.id,
            "name": dataset.name,
            "label": dataset.label,
            "technique_ids": dataset.technique_ids,
            "event_count": len(dataset.events),
            "alerts": alerts,
            "detected": dataset.label == "malicious" and alerts > 0,
            "relevant_rules": len(relevant),
        })

    techniques: dict[str, dict[str, Any]] = {}
    for dataset, result in zip(datasets, dataset_results, strict=True):
        if dataset.label != "malicious":
            continue
        for technique in dataset.technique_ids:
            entry = techniques.setdefault(technique, {"technique": technique, "datasets": 0, "detected_datasets": 0})
            entry["datasets"] += 1
            entry["detected_datasets"] += int(result["detected"])
    for i, rule in enumerate(rules):
        for technique in rule.techniques:
            entry = techniques.setdefault(technique, {"technique": technique, "datasets": 0, "detected_datasets": 0})
            entry.setdefault("rules", 0)
            entry["rules"] = entry.get("rules", 0) + 1

    malicious_alerts = sum(r["malicious_hits"] for r in rule_reports)
    benign_alerts = sum(r["benign_hits"] for r in rule_reports)
    detected = sum(1 for r in dataset_results if r["detected"])
    return {
        "summary": {
            "rules": len(rules),
            "rules_with_errors": sum(1 for r in rule_reports if r["error"]),
            "malicious_datasets": len(malicious),
            "benign_datasets": len(benign),
            "detected_malicious_datasets": detected,
            "dataset_recall": round(detected / len(malicious), 4) if malicious else None,
            "malicious_alerts": malicious_alerts,
            "benign_alerts": benign_alerts,
            "alert_precision": round(malicious_alerts / (malicious_alerts + benign_alerts), 4)
            if malicious_alerts + benign_alerts
            else None,
        },
        "rules": rule_reports,
        "datasets": dataset_results,
        "techniques": sorted(
            ({"rules": 0, **entry} for entry in techniques.values()), key=lambda e: e["technique"]
        ),
        "truncated": truncated,
        "elapsed_ms": round((time.monotonic() - started) * 1000, 1),
    }


__all__ = ["CompiledRule", "LabDataset", "evaluate"]
