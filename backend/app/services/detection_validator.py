import json
import re
from pathlib import Path
from typing import Any

import yaml

from app.schemas.detection import (
    DetectionEvent,
    DetectionMetrics,
    DetectionValidationResult,
)
from app.services.attack_knowledge import ATTACKKnowledgeService


class DetectionValidationService:
    def __init__(
        self,
        attack_knowledge: ATTACKKnowledgeService | None = None,
        fixture_path: str | None = None,
    ):
        self.attack_knowledge = attack_knowledge or ATTACKKnowledgeService()
        self.fixture_path = fixture_path or str(
            Path(__file__).parents[1] / "data" / "detection_events.json"
        )

    def validate(
        self,
        artifact_type: str,
        content: str,
        *,
        technique_id: str | None = None,
        events: list[DetectionEvent] | None = None,
    ) -> DetectionValidationResult:
        stages = {
            "syntax": False,
            "schema": False,
            "telemetry": False,
            "attack_mapping": False,
            "malicious_event_testing": False,
            "benign_event_testing": False,
        }
        errors: list[str] = []
        parsed: Any = None
        try:
            parsed = self._syntax_validate(artifact_type, content)
            stages["syntax"] = True
        except ValueError as error:
            errors.append(str(error))

        if stages["syntax"]:
            stages["schema"] = self._schema_validate(artifact_type, parsed, errors)
            stages["telemetry"] = self._telemetry_validate(
                artifact_type, parsed, errors
            )
            if technique_id:
                stages["attack_mapping"] = not bool(
                    self.attack_knowledge.validate_node(technique_id, self._tactic(parsed))
                )
                if not stages["attack_mapping"]:
                    errors.append(f"ATT&CK mapping validation failed: {technique_id}")
            else:
                stages["attack_mapping"] = False
                errors.append("ATT&CK mapping validation requires a technique ID")

        metrics = DetectionMetrics()
        if all(stages[key] for key in ("syntax", "schema", "telemetry", "attack_mapping")):
            test_events = events or self._load_fixture_events()
            metrics = self._test_events(artifact_type, parsed, test_events)
            stages["malicious_event_testing"] = any(
                event.malicious for event in test_events
            ) and metrics.fn == 0
            stages["benign_event_testing"] = any(
                not event.malicious for event in test_events
            ) and metrics.fp == 0
            if not stages["malicious_event_testing"]:
                errors.append("Malicious event testing failed")
            if not stages["benign_event_testing"]:
                errors.append("Benign event testing failed")

        passed_structural = all(
            stages[key] for key in ("syntax", "schema", "telemetry", "attack_mapping")
        )
        passed_tests = stages["malicious_event_testing"] and stages["benign_event_testing"]
        if not passed_structural:
            state = "FAILED"
        elif not passed_tests:
            state = "SYNTAX_VALID"
        else:
            state = "PRODUCTION_CANDIDATE"
        if passed_structural and (stages["malicious_event_testing"] or stages["benign_event_testing"]):
            state = "TESTED" if not passed_tests else state

        return DetectionValidationResult(
            artifact_type=artifact_type,
            state=state,
            stage_results=stages,
            errors=errors,
            metrics=metrics,
        )

    def _syntax_validate(self, artifact_type: str, content: str) -> Any:
        if artifact_type == "sigma":
            try:
                documents = list(yaml.safe_load_all(content))
                return documents[0] if len(documents) == 1 else documents
            except yaml.YAMLError as error:
                raise ValueError(f"Sigma syntax validation failed: {error}") from error
        if artifact_type not in {"kql", "spl"}:
            raise ValueError(f"Unsupported detection artifact type: {artifact_type}")
        if not content.strip() or content.count("'") % 2 or content.count('"') % 2:
            raise ValueError(f"{artifact_type.upper()} syntax validation failed")
        return content

    def _schema_validate(self, artifact_type: str, parsed: Any, errors: list[str]) -> bool:
        if artifact_type == "sigma":
            documents = parsed if isinstance(parsed, list) else [parsed]
            valid = True
            for document in documents:
                missing = {"title", "logsource", "detection"} - set(document or {})
                if missing:
                    errors.append(f"Sigma schema missing fields: {sorted(missing)}")
                    valid = False
                elif not isinstance(document.get("detection"), dict):
                    valid = False
            return valid
        if artifact_type == "kql":
            return " where " in f" {parsed.lower()} "
        return "search" in parsed.lower() or "index=" in parsed.lower()

    def _telemetry_validate(self, artifact_type: str, parsed: Any, errors: list[str]) -> bool:
        if artifact_type == "sigma":
            documents = parsed if isinstance(parsed, list) else [parsed]
            valid = all(
                bool(document.get("logsource"))
                and bool(document.get("detection", {}).get("selection"))
                for document in documents
            )
        elif artifact_type == "kql":
            valid = bool(re.search(r"\b[A-Za-z][A-Za-z0-9_]*\b", parsed))
        else:
            valid = "index=" in parsed or "sourcetype=" in parsed
        if not valid:
            errors.append("Telemetry requirements are not satisfied")
        return valid

    def _test_events(self, artifact_type: str, parsed: Any, events: list[DetectionEvent]) -> DetectionMetrics:
        values = [event.malicious for event in events]
        predictions = [self._matches(artifact_type, parsed, event.event) for event in events]
        tp = sum(predicted and actual for predicted, actual in zip(predictions, values, strict=False))
        fp = sum(predicted and not actual for predicted, actual in zip(predictions, values, strict=False))
        tn = sum(not predicted and not actual for predicted, actual in zip(predictions, values, strict=False))
        fn = sum(not predicted and actual for predicted, actual in zip(predictions, values, strict=False))
        precision = tp / (tp + fp) if tp + fp else 0.0
        recall = tp / (tp + fn) if tp + fn else 0.0
        f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
        return DetectionMetrics(tp=tp, fp=fp, tn=tn, fn=fn, precision=precision, recall=recall, f1=f1)

    def _matches(self, artifact_type: str, parsed: Any, event: dict[str, Any]) -> bool:
        if artifact_type == "sigma":
            if isinstance(parsed, list):
                return any(self._matches(artifact_type, document, event) for document in parsed)
            selection = parsed.get("detection", {}).get("selection", {})
            return all(self._contains_event_value(event, key, value) for key, value in selection.items())
        terms = re.findall(r"(?:endswith|contains|search|=)\s*['\"]([^'\"]+)", parsed, re.IGNORECASE)
        return any(self._contains_event_value(event, "CommandLine", term) for term in terms)

    @staticmethod
    def _contains_event_value(event: dict[str, Any], key: str, expected: Any) -> bool:
        field = key.split("|", 1)[0].lower()
        actual = next((value for name, value in event.items() if name.lower() == field), None)
        expected_value = str(expected).lower().strip("*").lstrip("\\")
        return actual is not None and expected_value in str(actual).lower()

    @staticmethod
    def _tactic(parsed: Any) -> str:
        if isinstance(parsed, list):
            parsed = parsed[0] if parsed else {}
        tags = parsed.get("tags", []) if isinstance(parsed, dict) else []
        tactic = next((tag[6:] for tag in tags if tag.startswith("attack.")), "TA0002")
        return tactic.upper() if tactic.startswith("TA") else "TA0002"

    def _load_fixture_events(self) -> list[DetectionEvent]:
        with Path(self.fixture_path).open(encoding="utf-8") as stream:
            return [DetectionEvent.model_validate(item) for item in json.load(stream)]