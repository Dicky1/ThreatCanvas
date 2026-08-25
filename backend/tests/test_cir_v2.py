from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from app.schemas.cir import CIRSpecification, RelationshipType


def test_legacy_cir_shape_remains_compatible():
    cir = CIRSpecification(
        cir_version="1.0",
        scenario_id="legacy-scenario",
        attack_graph={
            "nodes": [
                {
                    "step_id": "step-1",
                    "tactic": "TA0001",
                    "technique": "T1566",
                    "target": "mailbox",
                    "action_type": "Email Delivery",
                    "evidence": ["malicious attachment"],
                }
            ],
            "edges": [],
        },
    )

    assert cir.attack_graph.nodes[0].evidence[0].description == "malicious attachment"
    assert cir.entities == []


def test_v2_entities_metadata_and_relationships_round_trip():
    timestamp = datetime(2026, 8, 25, tzinfo=timezone.utc)
    payload = {
        "scenario_id": "v2-scenario",
        "confidence": 0.9,
        "created_at": timestamp,
        "entities": [
            {
                "id": "actor-1",
                "entity_type": "threat_actor",
                "name": "Example Group",
                "confidence": 0.8,
                "provenance": "intel-report-1",
                "attributes": {"source": "report"},
            },
            {"id": "asset-1", "entity_type": "asset", "name": "Domain Controller"},
        ],
        "attack_graph": {
            "nodes": [
                {
                    "step_id": "step-1",
                    "tactic": "TA0001",
                    "technique": "T1566",
                    "target": "Domain Controller",
                    "action_type": "Email Delivery",
                    "entity_refs": ["actor-1", "asset-1"],
                    "evidence": [],
                }
            ],
            "edges": [
                {"from": "step-1", "to": "step-1", "relationship": "TARGETS"}
            ],
        },
    }

    cir = CIRSpecification.model_validate(payload)

    assert cir.cir_version == "2.0"
    assert cir.created_at == timestamp
    assert cir.entities[0].entity_type == "threat_actor"
    assert cir.attack_graph.edges[0].relationship == "TARGETS"
    assert {"USES", "TARGETS", "REQUIRES", "EXPLOITS", "PRODUCES", "DETECTED_BY", "COUNTERED_BY", "CONNECTED_TO"} == {
        value
        for value in RelationshipType.__args__
    }
    assert CIRSpecification.model_validate(cir.model_dump()).entities[1].name == (
        "Domain Controller"
    )


def test_entity_type_and_confidence_are_constrained():
    with pytest.raises(ValidationError):
        CIRSpecification(
            scenario_id="invalid",
            attack_graph={"nodes": [], "edges": []},
            entities=[{"id": "x", "entity_type": "unknown"}],
        )

    with pytest.raises(ValidationError):
        CIRSpecification(
            scenario_id="invalid",
            confidence=1.1,
            attack_graph={"nodes": [], "edges": []},
        )