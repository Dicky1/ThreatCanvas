"""Regression tests for the ATT&CK catalog and the detection pipeline:
- the shipped catalog covers all Enterprise techniques with official tactics
- ATT&CK v18+ tactics (Stealth / Defense Impairment) are not dropped
- detection validation checks every rule, not only Execution techniques
- generated KQL/SPL is structurally valid and escapes user-controlled text
"""

import re

import pytest
import yaml

from app.schemas.cir import CIRSpecification
from app.services.attack_knowledge import ATTACKKnowledgeService
from app.services.cir_normalizer import CIRNormalizer
from app.services.detection_validator import DetectionValidationService
from app.services.kql_compiler import KQLCompiler
from app.services.sigma_compiler import SigmaCompiler
from app.services.spl_compiler import SPLCompiler


def cir(*nodes):
    return CIRSpecification(
        scenario_id="detect-test",
        attack_graph={
            "nodes": [
                {"step_id": f"s{i}", "tactic": tactic, "technique": technique, "target": "WS01",
                 "action_type": "Step", "evidence": [evidence]}
                for i, (tactic, technique, evidence) in enumerate(nodes, start=1)
            ],
            "edges": [
                {"from": f"s{i}", "to": f"s{i + 1}", "relationship": "leads_to"}
                for i in range(1, len(nodes))
            ],
        },
    )


SCENARIO = cir(
    ("TA0001", "T1566.001", {"type": "file", "description": "Attachment invoice.docm delivered"}),
    ("TA0002", "T1059.001", {"type": "process", "description": "PowerShell ran Invoke-Expression"}),
    ("TA0003", "T1547.001", {"type": "registry",
                             "registry_key": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                             "registry_value": 'C:\\Users\\Public\\it"s.exe'}),
    ("TA0040", "T1486", {"type": "unknown", "description": "Files were encrypted"}),
)


# --- ATT&CK catalog -------------------------------------------------------

def test_default_catalog_covers_full_enterprise_matrix():
    service = ATTACKKnowledgeService()
    assert len(service.techniques) > 600
    assert service.version != "compatibility-catalog"
    for technique, tactic in [("T1071.001", "TA0011"), ("T1027", "TA0005"), ("T1547", "TA0003"),
                              ("T1204.002", "TA0002"), ("T1078", "TA0001")]:
        assert service.validate_node(technique, tactic) == [], technique


def test_builtin_fallback_uses_official_tactics():
    service = ATTACKKnowledgeService.__new__(ATTACKKnowledgeService)
    service.tactic_names = {}
    service._load_compatibility_catalog()
    assert service.resolve_technique("T1204").tactics == ("TA0002",)
    assert "TA0001" in service.resolve_technique("T1078").tactics


def test_bundle_with_renamed_and_new_tactics_is_not_dropped():
    bundle = {
        "type": "bundle",
        "spec_version": "2.1",
        "objects": [
            {"type": "x-mitre-tactic", "name": "Defense Impairment", "x_mitre_shortname": "defense-impairment",
             "external_references": [{"source_name": "mitre-attack", "external_id": "TA0112"}]},
            {"type": "attack-pattern", "name": "Impair Defenses",
             "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "defense-impairment"}],
             "external_references": [{"source_name": "mitre-attack", "external_id": "T1562"}]},
            {"type": "attack-pattern", "name": "Obfuscated Files or Information",
             "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "stealth"}],
             "external_references": [{"source_name": "mitre-attack", "external_id": "T1027"}]},
        ],
    }
    service = ATTACKKnowledgeService(bundle=bundle)
    assert service.resolve_technique("T1562").tactics == ("TA0112",)
    assert service.resolve_technique("T1027").tactics == ("TA0005",)
    assert service.tactic_names["TA0112"] == "Defense Impairment"


def test_normalizer_keeps_valid_tactic_and_fixes_wrong_one():
    spec = cir(
        ("TA0001", "T1204.002", {"description": "user opened file"}),
        ("initial-access", "t1078", {"description": "valid account login"}),
    )
    nodes = CIRNormalizer.normalize(spec).attack_graph.nodes
    assert (nodes[0].technique, nodes[0].tactic) == ("T1204.002", "TA0002")
    assert (nodes[1].technique, nodes[1].tactic) == ("T1078", "TA0001")


# --- Compilers --------------------------------------------------------------

def test_sigma_rules_use_standard_tags_and_skip_nodes_without_observables():
    content = SigmaCompiler(SCENARIO).compile()
    documents = [d for d in yaml.safe_load_all(content) if d]
    tags = {tag for document in documents for tag in document["tags"]}
    assert {"attack.initial_access", "attack.t1566.001", "attack.persistence", "attack.t1547.001"} <= tags
    assert "s4 (T1486)" in content.splitlines()[0]
    assert all(doc["detection"]["condition"] for doc in documents)


def test_kql_is_single_valid_union_with_escaped_strings():
    content = KQLCompiler(SCENARIO).compile()
    code = "\n".join(line for line in content.splitlines() if not line.startswith("//"))
    assert code.startswith("union")
    assert code.count("(") == code.count(")")
    assert "| union" not in code
    assert 'RegistryValueData contains "C:\\\\Users\\\\Public\\\\it\\"s.exe"' in code
    assert 'FileName =~ "powershell.exe"' in code


def test_spl_uses_append_subsearches_with_escaped_strings():
    content = SPLCompiler(SCENARIO).compile()
    lines = content.splitlines()
    assert lines[0].startswith("search index=")
    assert all(line.startswith("| append [ search ") and line.endswith(" ]") for line in lines[1:])
    assert 'Details="*C:\\\\Users\\\\Public\\\\it\\"s.exe*"' in content
    assert re.search(r'Image="\*\\\\powershell\.exe"', content)


# --- Validation ---------------------------------------------------------------

@pytest.mark.parametrize("artifact_type,compiler", [("sigma", SigmaCompiler), ("kql", KQLCompiler), ("spl", SPLCompiler)])
def test_generated_artifacts_pass_validation_for_non_execution_techniques(artifact_type, compiler):
    result = DetectionValidationService().validate(
        artifact_type, compiler(SCENARIO).compile(), technique_id="T1566.001"
    )
    assert result.stage_results["attack_mapping"], result.errors
    assert result.state == "PRODUCTION_CANDIDATE", result.errors
    assert result.metrics.tp == 1 and result.metrics.fp == 0


def test_validation_rejects_wrong_tactic_on_any_rule():
    rule = """title: wrong
logsource: {category: process_creation, product: windows}
detection:
  selection: {Image|endswith: '\\\\powershell.exe'}
  condition: selection
tags: [attack.impact, attack.t1059.001]
"""
    result = DetectionValidationService().validate("sigma", rule, technique_id="T1059.001")
    assert result.state == "FAILED"
    assert any("T1059.001 is not mapped" in error for error in result.errors)


def test_validation_fails_when_no_rule_could_be_generated():
    only_unobservable = cir(("TA0040", "T1486", {"description": "Files were encrypted"}))
    for artifact_type, compiler in [("sigma", SigmaCompiler), ("kql", KQLCompiler), ("spl", SPLCompiler)]:
        result = DetectionValidationService().validate(
            artifact_type, compiler(only_unobservable).compile(), technique_id="T1486"
        )
        assert result.state == "FAILED", artifact_type


def test_unrelated_malicious_fixtures_are_not_counted_as_misses():
    rule = """title: rdp
logsource: {category: process_creation, product: windows}
detection:
  selection: {Image|endswith: '\\\\mstsc.exe'}
  condition: selection
tags: [attack.lateral_movement, attack.t1021.001]
"""
    result = DetectionValidationService().validate("sigma", rule, technique_id="T1021.001")
    assert result.stage_results["attack_mapping"]
    assert result.metrics.fn == 0
    assert any("No malicious test events" in error for error in result.errors)


def test_corrupt_full_bundle_falls_back_to_catalog(tmp_path, monkeypatch):
    import app.services.attack_knowledge as attack_knowledge

    broken = tmp_path / "enterprise-attack.json"
    broken.write_text('{"type": "bund', encoding="utf-8")  # interrupted download
    monkeypatch.setattr(attack_knowledge, "DEFAULT_BUNDLE_PATH", broken)
    monkeypatch.delenv("ATTACK_STIX_PATH", raising=False)
    service = ATTACKKnowledgeService()
    assert len(service.techniques) > 600
