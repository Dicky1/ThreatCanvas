import io
import zipfile

import pytest

from app.api.endpoints import parser
from app.schemas.cir import CIRSpecification
from app.services.attack_knowledge import ATTACKKnowledgeService
from app.services.coverage_gap import InventoryError, analyze_gaps, parse_dettect, parse_rule_inventory

SIGMA_RULES = b"""
title: PowerShell download
id: 1
tags: [attack.execution, attack.t1059.001]
logsource: {category: process_creation, product: windows}
detection: {sel: {CommandLine|contains: DownloadString}, condition: sel}
---
title: Untagged rule
logsource: {category: process_creation}
detection: {sel: {Image: x}, condition: sel}
---
title: Run keys
tags: [attack.persistence, attack.t1547]
logsource: {category: registry_set, product: windows}
detection: {sel: {TargetObject|contains: Run}, condition: sel}
"""
CIR = {
    "scenario_id": "gap",
    "attack_graph": {"nodes": [
        {"step_id": "s1", "tactic": "TA0002", "technique": "T1059.001", "target": "WS01", "action_type": "Execution",
         "evidence": [{"type": "process", "image": "powershell.exe"}]},
        {"step_id": "s2", "tactic": "TA0003", "technique": "T1547.001", "target": "WS01", "action_type": "Persistence",
         "evidence": [{"description": "run key"}]},
        {"step_id": "s3", "tactic": "TA0040", "technique": "T1486", "target": "FS01", "action_type": "Encryption",
         "evidence": [{"description": "files encrypted"}]},
        {"step_id": "s4", "tactic": "TA0001", "technique": "T1566.001", "target": "mail", "action_type": "Phishing",
         "evidence": [{"description": "attachment"}]},
    ], "edges": []},
}
DETTECT_V11 = """
version: 1.1
file_type: data-source-administration
name: lab
data_sources:
  - data_source_name: Process Creation
    data_source:
      - applicable_to: [all]
        date_connected: 2026-01-01
        available_for_data_analytics: true
        data_quality: {device_completeness: 5, data_field_completeness: 4}
  - data_source_name: Windows Registry Key Modification
    data_source:
      - applicable_to: [all]
        date_connected:
        available_for_data_analytics: false
        data_quality: {device_completeness: 0}
  - data_source_name: Made-up Source
    data_source:
      - applicable_to: [all]
        available_for_data_analytics: true
"""
DETTECT_V10 = """
version: 1.0
file_type: data-source-administration
data_sources:
  - data_source_name: Command Execution
    date_connected: 2026-01-01
    data_quality: {device_completeness: 3}
"""


def test_sigma_zip_and_csv_inventory():
    result = parse_rule_inventory("rules.yml", SIGMA_RULES)
    assert [r.techniques for r in result.rules] == [["T1059.001"], ["T1547"]] and result.skipped == 1
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("rules/windows/a.yml", SIGMA_RULES)
        archive.writestr("rules/README.md", "ignored")
        archive.writestr("export.csv", "title,technique\nSplunk notable,T1486\nNo technique,\n")
    zipped = parse_rule_inventory("repo.zip", buffer.getvalue())
    assert len(zipped.rules) == 3 and zipped.rules[-1].source == "csv"
    with pytest.raises(InventoryError):
        parse_rule_inventory("x.csv", b"name\nfoo\n")
    with pytest.raises(InventoryError, match="No ATT&CK-tagged"):
        parse_rule_inventory("x.yml", b"title: t\ndetection: {condition: s, s: {a: b}}\n")


def test_dettect_formats():
    known = {"Process Creation", "Windows Registry Key Modification", "Command Execution"}
    available, unmatched = parse_dettect(DETTECT_V11, known)
    assert available == ["Process Creation"] and unmatched == ["Made-up Source"]
    assert parse_dettect(DETTECT_V10, known) == (["Command Execution"], [])
    with pytest.raises(InventoryError):
        parse_dettect("name: not dettect", known)


def test_gap_statuses():
    cir = CIRSpecification(**CIR)
    knowledge = ATTACKKnowledgeService()
    inventory = [{"title": "PowerShell download", "techniques": ["T1059.001"]}, {"title": "Run keys", "techniques": ["T1547"]}]
    result = analyze_gaps(cir, knowledge, inventory, ["Process Creation"], {"T1059.001"})
    status = {row["technique"]: row["status"] for row in result["techniques"]}
    assert status["T1059.001"] == "COVERED"  # rule + Process Creation collected
    assert status["T1547.001"] == "COVERED"  # parent-technique rule counts as related coverage
    assert status["T1486"] == "TELEMETRY_WITHOUT_RULE"  # Process Creation also observes T1486
    rows = {row["technique"]: row for row in result["techniques"]}
    assert rows["T1547.001"]["existing_rules"][0]["match"] == "related"
    assert "Windows Registry Key Modification" in rows["T1547.001"]["missing_data_components"]
    assert rows["T1059.001"]["generated_rule_available"] is True

    no_telemetry = analyze_gaps(cir, knowledge, inventory, [], set())
    status = {row["technique"]: row["status"] for row in no_telemetry["techniques"]}
    assert status["T1059.001"] == "RULE_WITHOUT_TELEMETRY" and status["T1486"] == "BLIND"
    assert no_telemetry["top_missing_data_components"][0]["data_component"] == "Process Creation"

    unknown_profile = analyze_gaps(cir, knowledge, [], None, set())
    assert {row["status"] for row in unknown_profile["techniques"]} == {"NO_RULE"}
    assert unknown_profile["summary"]["data_source_profile"] is False


@pytest.fixture()
def gap(api_client, make_user, monkeypatch):
    async def fake_llm(_):
        return CIRSpecification(**CIR)

    monkeypatch.setattr(parser, "parse_narrative_to_cir", fake_llm)
    alice = make_user("alice")
    scenario_id = api_client.post("/api/v1/parse", json={"scenario": "x"}, headers=alice).json()["id"]
    return alice, scenario_id


def test_gap_api_flow(api_client, gap):
    alice, scenario_id = gap
    imported = api_client.post("/api/v1/coverage-gap/rules", files={"file": ("rules.yml", SIGMA_RULES, "text/yaml")}, headers=alice)
    assert imported.status_code == 201 and imported.json() == {"imported": 2, "skipped_untagged": 1, "errors": []}
    assert api_client.get("/api/v1/coverage-gap/rules", headers=alice).json()["rules"] == 2

    catalog = api_client.get("/api/v1/coverage-gap/data-sources", headers=alice).json()
    assert catalog["configured"] is False and "Process Creation" in catalog["catalog"]
    assert api_client.put("/api/v1/coverage-gap/data-sources", json={"components": ["Nope"]}, headers=alice).status_code == 400
    dettect = api_client.post("/api/v1/coverage-gap/data-sources/dettect", files={"file": ("ds.yaml", DETTECT_V11, "text/yaml")}, headers=alice)
    assert dettect.status_code == 200 and dettect.json()["components"] == ["Process Creation"]

    analysis = api_client.get(f"/api/v1/coverage-gap/{scenario_id}", headers=alice).json()
    assert analysis["summary"]["covered"] == 2 and analysis["summary"]["inventory_rules"] == 2
    layer = api_client.get(f"/api/v1/coverage-gap/{scenario_id}/navigator", headers=alice).json()
    assert {t["techniqueID"] for t in layer["techniques"]} == {"T1059.001", "T1547.001", "T1486", "T1566.001"}

    replaced = api_client.post("/api/v1/coverage-gap/rules?replace=true", files={"file": ("r.csv", b"title,technique\nA,T1486\n", "text/csv")}, headers=alice)
    assert replaced.json()["imported"] == 1
    assert api_client.get("/api/v1/coverage-gap/rules", headers=alice).json()["rules"] == 1
    assert api_client.delete("/api/v1/coverage-gap/rules", headers=alice).json() == {"deleted": 1}


def test_gap_data_is_private(api_client, make_user, gap):
    alice, scenario_id = gap
    api_client.post("/api/v1/coverage-gap/rules", files={"file": ("rules.yml", SIGMA_RULES, "text/yaml")}, headers=alice)
    api_client.put("/api/v1/coverage-gap/data-sources", json={"components": ["Process Creation"]}, headers=alice)
    mallory = make_user("mallory")
    assert api_client.get(f"/api/v1/coverage-gap/{scenario_id}", headers=mallory).status_code == 404
    assert api_client.get("/api/v1/coverage-gap/rules", headers=mallory).json()["rules"] == 0
    assert api_client.get("/api/v1/coverage-gap/data-sources", headers=mallory).json()["configured"] is False
    assert api_client.delete("/api/v1/coverage-gap/rules", headers=mallory).json() == {"deleted": 0}
    assert api_client.get("/api/v1/coverage-gap/rules", headers=alice).json()["rules"] == 2
