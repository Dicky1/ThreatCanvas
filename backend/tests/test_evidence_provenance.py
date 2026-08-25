from datetime import datetime, timezone

from pydantic import ValidationError
import pytest

from app.schemas.cir import CIRSpecification
from app.services.evidence_provenance import EvidenceProvenanceEngine


def make_cir(evidence):
    return CIRSpecification(
        scenario_id="provenance-test",
        attack_graph={
            "nodes": [
                {
                    "step_id": "step-1",
                    "tactic": "TA0002",
                    "technique": "T1059.001",
                    "target": "workstation-1",
                    "action_type": "Execution",
                    "evidence": [evidence],
                }
            ],
            "edges": [],
        },
    )


def test_engine_adds_traceable_provenance_without_mutating_input():
    original = make_cir({"description": "PowerShell command observed"})
    timestamp = datetime(2026, 8, 25, tzinfo=timezone.utc)

    enriched = EvidenceProvenanceEngine.enrich(
        original, source="incident-42", now=timestamp
    )
    evidence = enriched.attack_graph.nodes[0].evidence[0]

    assert original.attack_graph.nodes[0].evidence[0].source is None
    assert evidence.evidence_text == "PowerShell command observed"
    assert evidence.source == "incident-42"
    assert evidence.timestamp == timestamp
    assert evidence.asset == "workstation-1"
    assert evidence.inference_method == "LLM_INFERENCE"
    assert evidence.validation_state == "LLM_INFERRED"


def test_engine_redacts_secrets_from_evidence_fields():
    cir = make_cir(
        {
            "description": "api_key=super-secret-token Bearer abc.def.ghi",
            "command_line": "--password=hunter2",
        }
    )

    evidence = EvidenceProvenanceEngine.enrich(cir).attack_graph.nodes[0].evidence[0]

    assert "super-secret-token" not in evidence.description
    assert "abc.def.ghi" not in evidence.description
    assert "hunter2" not in evidence.command_line
    assert "[REDACTED]" in evidence.description


def test_enriched_cir_is_json_serializable_for_persistence():
    cir = EvidenceProvenanceEngine.enrich(
        make_cir("observable"),
        now=datetime(2026, 8, 25, tzinfo=timezone.utc),
    )

    serialized = cir.model_dump(mode="json")

    assert serialized["attack_graph"]["nodes"][0]["evidence"][0]["timestamp"] == (
        "2026-08-25T00:00:00Z"
    )


def test_validation_states_are_constrained_and_existing_evidence_loads():
    legacy = make_cir("legacy observable text")
    assert legacy.attack_graph.nodes[0].evidence[0].description == (
        "legacy observable text"
    )

    with pytest.raises(ValidationError):
        make_cir({"validation_state": "NOT_A_STATE"})