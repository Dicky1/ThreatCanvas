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
from app.services.attack_knowledge import TACTIC_IDS, ATTACKKnowledgeService

# KQL (Defender XDR) / SPL column -> event keys in the Sysmon-style fixtures.
QUERY_FIELD_TO_EVENT = {
    "filename": ("Image", "TargetFilename"),
    "folderpath": ("Image", "TargetFilename"),
    "initiatingprocessfolderpath": ("ParentImage",),
    "initiatingprocesscommandline": ("ParentCommandLine",),
    "processcommandline": ("CommandLine",),
    "sha256": ("Hashes",),
    "registrykey": ("TargetObject",),
    "registryvaluedata": ("Details",),
    "remoteip": ("DestinationIp",),
    "remoteurl": ("DestinationHostname",),
}
IGNORED_QUERY_FIELDS = {"tactic", "technique", "stepid", "step_id", "sourcetype", "source", "index", "message", "eventcode"}


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
            mapping_errors = self._attack_mapping_errors(artifact_type, parsed, technique_id)
            stages["attack_mapping"] = not mapping_errors
            errors.extend(mapping_errors)

        metrics = DetectionMetrics()
        if all(stages[key] for key in ("syntax", "schema", "telemetry", "attack_mapping")):
            test_events = events or self._relevant_fixture_events(
                {technique for technique, _ in self._attack_pairs(artifact_type, parsed)}
                or ({technique_id} if technique_id else set())
            )
            metrics = self._test_events(artifact_type, parsed, test_events)
            stages["malicious_event_testing"] = any(
                event.malicious for event in test_events
            ) and metrics.fn == 0
            stages["benign_event_testing"] = any(
                not event.malicious for event in test_events
            ) and metrics.fp == 0
            if not stages["malicious_event_testing"]:
                if not any(event.malicious for event in test_events):
                    errors.append(
                        "No malicious test events for this artifact's techniques; "
                        "supply events in the request to measure recall"
                    )
                else:
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

    @staticmethod
    def _sigma_documents(parsed: Any) -> list[dict]:
        documents = parsed if isinstance(parsed, list) else [parsed]
        return [document for document in documents if document is not None]

    @staticmethod
    def _unbalanced_quotes(content: str) -> bool:
        unescaped = re.sub(r"\\.", "", content)
        return bool(unescaped.count("'") % 2 or unescaped.count('"') % 2)

    def _syntax_validate(self, artifact_type: str, content: str) -> Any:
        if artifact_type == "sigma":
            try:
                documents = [d for d in yaml.safe_load_all(content) if d is not None]
            except yaml.YAMLError as error:
                raise ValueError(f"Sigma syntax validation failed: {error}") from error
            if not documents:
                raise ValueError("Sigma artifact contains no rules")
            if not all(isinstance(document, dict) for document in documents):
                raise ValueError("Sigma syntax validation failed: every document must be a mapping")
            return documents[0] if len(documents) == 1 else documents
        if artifact_type not in {"kql", "spl"}:
            raise ValueError(f"Unsupported detection artifact type: {artifact_type}")
        # Ignore comment lines (KQL "//") when checking structure.
        code = "\n".join(line for line in content.splitlines() if not line.lstrip().startswith("//"))
        if not code.strip() or self._unbalanced_quotes(code):
            raise ValueError(f"{artifact_type.upper()} syntax validation failed")
        if code.count("(") != code.count(")") or code.count("[") != code.count("]"):
            raise ValueError(f"{artifact_type.upper()} syntax validation failed: unbalanced brackets")
        return code

    def _schema_validate(self, artifact_type: str, parsed: Any, errors: list[str]) -> bool:
        if artifact_type == "sigma":
            valid = True
            for document in self._sigma_documents(parsed):
                missing = {"title", "logsource", "detection"} - set(document)
                if missing:
                    errors.append(f"Sigma schema missing fields: {sorted(missing)}")
                    valid = False
                elif not isinstance(document.get("detection"), dict) or "condition" not in document["detection"]:
                    errors.append("Sigma detection must be a mapping with a condition")
                    valid = False
            return valid
        if artifact_type == "kql":
            return " where " in f" {parsed.lower()} "
        return "search" in parsed.lower() or "index=" in parsed.lower()

    @staticmethod
    def _sigma_selections(document: dict) -> list[dict]:
        detection = document.get("detection", {}) if isinstance(document, dict) else {}
        return [
            value
            for key, value in detection.items()
            if key.startswith("selection") and isinstance(value, dict) and value
        ]

    def _telemetry_validate(self, artifact_type: str, parsed: Any, errors: list[str]) -> bool:
        if artifact_type == "sigma":
            valid = all(
                bool(document.get("logsource")) and bool(self._sigma_selections(document))
                for document in self._sigma_documents(parsed)
            )
        elif artifact_type == "kql":
            valid = bool(re.search(r"\b[A-Za-z][A-Za-z0-9_]*\b", parsed))
        else:
            valid = any(marker in parsed for marker in ("index=", "sourcetype=", "source="))
        if not valid:
            errors.append("Telemetry requirements are not satisfied")
        return valid

    def _attack_pairs(self, artifact_type: str, parsed: Any) -> list[tuple[str, tuple[str, ...]]]:
        """(technique, candidate tactics) for every rule/query in the artifact."""
        pairs: list[tuple[str, tuple[str, ...]]] = []
        if artifact_type == "sigma":
            for document in self._sigma_documents(parsed):
                techniques, tactics = [], []
                for tag in document.get("tags", []) or []:
                    value = str(tag).lower()
                    if not value.startswith("attack."):
                        continue
                    value = value[len("attack."):]
                    if re.fullmatch(r"t\d{4}([._]\d{3})?", value):
                        techniques.append(value.upper().replace("_", "."))
                    elif re.fullmatch(r"ta\d{4}", value):
                        tactics.append(value.upper())
                    else:
                        tactic_id = TACTIC_IDS.get(value.replace("_", " ").replace("-", " "))
                        if tactic_id:
                            tactics.append(tactic_id)
                pairs.extend((technique, tuple(tactics)) for technique in techniques)
            return pairs
        for tactic, technique in re.findall(
            r"tactic\s*=\s*[\"'](TA\d{4})[\"']\s*,\s*technique\s*=\s*[\"'](T\d{4}(?:\.\d{3})?)[\"']",
            parsed,
            re.IGNORECASE,
        ):
            pairs.append((technique.upper(), (tactic.upper(),)))
        return pairs

    def _attack_mapping_errors(self, artifact_type: str, parsed: Any, technique_id: str | None) -> list[str]:
        pairs = self._attack_pairs(artifact_type, parsed)
        if not pairs:
            if not technique_id:
                return ["ATT&CK mapping validation requires a technique ID"]
            # Artifact carries no technique tag: check the supplied technique
            # against whatever tactic it declares (if any).
            tactics: tuple[str, ...] = ()
            if artifact_type == "sigma":
                for document in self._sigma_documents(parsed):
                    for tag in document.get("tags", []) or []:
                        value = str(tag).lower().removeprefix("attack.")
                        if re.fullmatch(r"ta\d{4}", value):
                            tactics += (value.upper(),)
                        elif value.replace("_", " ") in TACTIC_IDS:
                            tactics += (TACTIC_IDS[value.replace("_", " ")],)
            pairs = [(technique_id.upper(), tactics)]

        errors = []
        for technique, tactics in pairs:
            known = self.attack_knowledge.resolve_technique(technique)
            if known is None or known.deprecated:
                errors.append(f"ATT&CK mapping validation failed: {technique} is unknown or deprecated")
            elif tactics and not set(tactics) & set(known.tactics):
                errors.append(
                    f"ATT&CK mapping validation failed: {technique} is not mapped to {', '.join(tactics)}"
                )
        return errors

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
            for document in self._sigma_documents(parsed):
                selections = self._sigma_selections(document)
                condition = str(document.get("detection", {}).get("condition", "")).lower()
                hits = [self._selection_matches(selection, event) for selection in selections]
                if hits and (all(hits) if condition.startswith("all of") else any(hits)):
                    return True
            return False
        # KQL / SPL: any field=value term from the query matching the event.
        for column, value in self._query_terms(artifact_type, parsed):
            keys = QUERY_FIELD_TO_EVENT.get(column.lower(), (column,))
            if any(self._contains_event_value(event, key, value) for key in keys):
                return True
        return False

    def _selection_matches(self, selection: dict[str, Any], event: dict[str, Any]) -> bool:
        for key, expected in selection.items():
            values = expected if isinstance(expected, list) else [expected]
            checks = [self._contains_event_value(event, key, value) for value in values]
            if not (all(checks) if key.endswith("|all") else any(checks)):
                return False
        return True

    @staticmethod
    def _query_terms(artifact_type: str, parsed: str) -> list[tuple[str, str]]:
        if artifact_type == "kql":
            pattern = r"(\w+)\s*(?:=~|==|contains|endswith|startswith|has)\s*\"((?:\\.|[^\"\\])*)\""
        else:
            pattern = r"(\w+)\s*=\s*\"((?:\\.|[^\"\\])*)\""
        terms = []
        for column, raw in re.findall(pattern, parsed, re.IGNORECASE):
            if column.lower() in IGNORED_QUERY_FIELDS:
                continue
            value = re.sub(r"\\(.)", r"\1", raw)
            terms.append((column, value))
        return terms

    @staticmethod
    def _contains_event_value(event: dict[str, Any], key: str, expected: Any) -> bool:
        field = key.split("|", 1)[0].lower()
        actual = next((value for name, value in event.items() if name.lower() == field), None)
        expected_value = str(expected).lower().strip("*").lstrip("\\")
        return actual is not None and expected_value in str(actual).lower()

    def _relevant_fixture_events(self, techniques: set[str]) -> list[DetectionEvent]:
        """Benign fixtures always apply; malicious ones only for matching techniques
        (a sub-technique matches its parent and vice versa)."""
        def related(event_technique: str | None) -> bool:
            if not event_technique or not techniques:
                return True
            parent = event_technique.split(".")[0]
            return any(t == event_technique or t.split(".")[0] == parent for t in techniques)

        return [
            event
            for event in self._load_fixture_events()
            if not event.malicious or related(event.technique_id)
        ]

    def _load_fixture_events(self) -> list[DetectionEvent]:
        with Path(self.fixture_path).open(encoding="utf-8") as stream:
            return [DetectionEvent.model_validate(item) for item in json.load(stream)]