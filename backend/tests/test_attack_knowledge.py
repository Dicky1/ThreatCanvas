import pytest

from app.services.attack_knowledge import ATTACKKnowledgeService
from app.services.cir_validator import CIRValidator
from app.schemas.cir import CIRSpecification


def bundle(*objects):
    return {"type": "bundle", "spec_version": "2.0", "objects": list(objects)}


def attack_pattern(identifier, name, tactic="execution", **extra):
    return {
        "type": "attack-pattern",
        "name": name,
        "kill_chain_phases": [
            {"kill_chain_name": "mitre-attack", "phase_name": tactic}
        ],
        "external_references": [
            {"source_name": "mitre-attack", "external_id": identifier}
        ],
        **extra,
    }


def cir(technique, tactic="TA0002"):
    return CIRSpecification(
        scenario_id="attack-knowledge-test",
        attack_graph={
            "nodes": [
                {
                    "step_id": "step-1",
                    "tactic": tactic,
                    "technique": technique,
                    "target": "host-1",
                    "action_type": "Execution",
                    "evidence": [{"description": "observed"}],
                }
            ],
            "edges": [],
        },
    )


def test_valid_technique_resolves_name_tactic_and_data_sources():
    service = ATTACKKnowledgeService(
        bundle=bundle(
            attack_pattern(
                "T1059",
                "Command and Scripting Interpreter",
                x_mitre_data_sources=["Command: Command Execution"],
                **{"x_mitre_version": "15.1"},
            )
        )
    )
    resolved = service.resolve_cir(cir("T1059"))

    assert service.resolve_technique_name("t1059") == "Command and Scripting Interpreter"
    assert resolved.attack_graph.nodes[0].technique_name == "Command and Scripting Interpreter"
    assert resolved.attack_graph.nodes[0].attack_data_sources == ["Command: Command Execution"]
    assert resolved.attack_graph.nodes[0].attack_version == "15.1"
    assert resolved.attack_version == "15.1"
    assert CIRValidator.validate(resolved, service)["valid"]


def test_invalid_technique_does_not_pass_validation():
    service = ATTACKKnowledgeService(bundle=bundle())
    report = CIRValidator.validate(cir("T9999"), service)

    assert not report["valid"]
    assert any("Unknown ATT&CK technique" in error for error in report["groups"]["MITRE"]["errors"])


def test_valid_subtechnique_resolves_and_lists_under_parent():
    service = ATTACKKnowledgeService(
        bundle=bundle(
            attack_pattern("T1059", "Command and Scripting Interpreter"),
            attack_pattern(
                "T1059.001",
                "PowerShell",
                x_mitre_is_subtechnique=True,
                x_mitre_parent_attack_id="T1059",
            ),
        )
    )

    assert service.resolve_technique("T1059.001").parent_id == "T1059"
    assert [item.technique_id for item in service.resolve_subtechniques("T1059")] == [
        "T1059.001"
    ]


def test_deprecated_technique_is_rejected():
    service = ATTACKKnowledgeService(
        bundle=bundle(attack_pattern("T1000", "Old Technique", revoked=True))
    )
    report = CIRValidator.validate(cir("T1000"), service)

    assert not report["valid"]
    assert any("Deprecated ATT&CK technique" in error for error in report["groups"]["MITRE"]["errors"])


def test_incorrect_tactic_mapping_is_rejected():
    service = ATTACKKnowledgeService(
        bundle=bundle(attack_pattern("T1059", "Command and Scripting Interpreter"))
    )
    report = CIRValidator.validate(cir("T1059", tactic="TA0001"), service)

    assert not report["valid"]
    assert any("not mapped" in error for error in report["groups"]["MITRE"]["errors"])


def test_non_stix_bundle_is_rejected():
    with pytest.raises(ValueError):
        ATTACKKnowledgeService(bundle={"type": "not-a-bundle"})