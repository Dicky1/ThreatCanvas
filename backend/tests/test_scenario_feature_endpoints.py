"""Regression tests for scenario features that previously crashed with 500:
ATT&CK Navigator export, Markdown executive report, D3FEND copilot and the
scenario chat (all called a missing ScenarioRepository.get_scenario), plus
parsing techniques that were missing from the old fallback ATT&CK catalog.
"""

from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.api.endpoints import chat, parser
from app.core.database import Base, get_db
from app.main import app
from app.schemas.cir import CIRSpecification

PASSWORD = "Str0ng-pass-123!"


def make_cir(nodes):
    return {
        "scenario_id": "feature-test",
        "attack_graph": {
            "nodes": [
                {
                    "step_id": f"s{i}",
                    "tactic": tactic,
                    "technique": technique,
                    "target": "WS01",
                    "action_type": action,
                    "evidence": [{"type": "process", "description": description}],
                }
                for i, (tactic, technique, action, description) in enumerate(nodes, start=1)
            ],
            "edges": [
                {"from": f"s{i}", "to": f"s{i + 1}", "relationship": "leads_to"}
                for i in range(1, len(nodes))
            ],
        },
    }


RANSOMWARE = [
    ("TA0001", "T1566.001", "Email Delivery", "Attachment invoice.docm opened"),
    # Deliberately tagged with the wrong tactic: User Execution is TA0002.
    ("TA0001", "T1204.002", "User Execution", "User opened the malicious file"),
    ("TA0002", "T1059.001", "Execution", "PowerShell ran Invoke-Expression"),
    ("TA0011", "T1071.001", "Command and Control", "Beacon to evil-cdn.xyz over HTTPS"),
    ("TA0040", "T1486", "Encryption", "Files encrypted"),
]


@pytest.fixture()
def client(monkeypatch):
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    Base.metadata.create_all(bind=engine)

    def override_get_db():
        db = TestingSessionLocal()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


@pytest.fixture()
def auth(client):
    client.post(
        "/api/v1/auth/register",
        json={"username": "analyst", "email": "analyst@example.com", "full_name": "A", "password": PASSWORD},
    )
    token = client.post("/api/v1/auth/login", data={"username": "analyst", "password": PASSWORD}).json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


def parse(client, auth, monkeypatch, nodes):
    async def fake_llm(_narrative):
        return CIRSpecification(**make_cir(nodes))

    monkeypatch.setattr(parser, "parse_narrative_to_cir", fake_llm)
    return client.post("/api/v1/parse", json={"scenario": "line one\nline two"}, headers=auth)


@pytest.fixture()
def scenario_id(client, auth, monkeypatch):
    response = parse(client, auth, monkeypatch, RANSOMWARE)
    assert response.status_code == 200, response.text
    return response.json()["id"]


def test_parse_accepts_techniques_outside_old_fallback_catalog(client, auth, monkeypatch):
    for technique, tactic in [("T1071.001", "TA0011"), ("T1027", "TA0005"), ("T1547", "TA0003")]:
        response = parse(client, auth, monkeypatch, [(tactic, technique, "Step", "observed")])
        assert response.status_code == 200, (technique, response.text)


def test_parse_corrects_tactic_to_official_attack_mapping(client, auth, monkeypatch):
    response = parse(client, auth, monkeypatch, RANSOMWARE)
    tactics = {n["technique"]: n["tactic"] for n in response.json()["cir"]["attack_graph"]["nodes"]}
    assert tactics["T1204.002"] == "TA0002"
    assert tactics["T1566.001"] == "TA0001"


def test_navigator_export(client, auth, scenario_id):
    response = client.get(f"/api/v1/export/navigator/{scenario_id}", headers=auth)
    assert response.status_code == 200, response.text
    layer = response.json()
    assert {t["techniqueID"] for t in layer["techniques"]} >= {"T1566.001", "T1486"}
    assert layer["versions"]["attack"].isdigit()


def test_markdown_report(client, auth, scenario_id):
    response = client.get(f"/api/v1/export/report/markdown/{scenario_id}", headers=auth)
    assert response.status_code == 200, response.text
    assert "# Executive Threat Assessment Report" in response.text
    assert "> line one\n> line two" in response.text


def test_d3fend_copilot(client, auth, scenario_id):
    response = client.get(f"/api/v1/d3fend/{scenario_id}", headers=auth)
    assert response.status_code == 200, response.text
    assert {r["technique_id"] for r in response.json()["remediations"]} >= {"T1059.001"}


def test_scenario_chat(client, auth, scenario_id, monkeypatch):
    captured = {}

    async def fake_create(**kwargs):
        captured.update(kwargs)
        return SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(content="Block PowerShell."))])

    monkeypatch.setattr(chat.client.chat.completions, "create", fake_create)
    response = client.post(
        f"/api/v1/chat/{scenario_id}",
        json={"messages": [{"role": "user", "content": "How do I stop this?"}]},
        headers=auth,
    )
    assert response.status_code == 200, response.text
    assert response.json()["reply"] == "Block PowerShell."
    assert "T1059.001" in captured["messages"][0]["content"]


@pytest.mark.parametrize("path", ["export/navigator", "export/report/markdown", "d3fend"])
def test_unknown_scenario_returns_404(client, auth, path):
    assert client.get(f"/api/v1/{path}/does-not-exist", headers=auth).status_code == 404
