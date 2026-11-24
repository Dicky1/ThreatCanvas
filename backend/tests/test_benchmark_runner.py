import json

import pytest

from app.core import config
from app.schemas.cir import CIRSpecification
from app.services import llm_client, llm_parser
from app.services.attack_knowledge import ATTACKKnowledgeService
from app.services.benchmark_runner import load_cases, ordering_accuracy, score


def cir_for(techniques):
    knowledge = ATTACKKnowledgeService()
    return CIRSpecification(scenario_id="b", attack_graph={"nodes": [
        {"step_id": f"s{i}", "tactic": (knowledge.resolve_technique(t).tactics or ["TA0002"])[0] if knowledge.resolve_technique(t) else "TA0002",
         "technique": t, "target": "host", "action_type": "step", "evidence": [{"description": "e"}]}
        for i, t in enumerate(techniques)], "edges": []})


def test_bundled_cases_are_valid_current_attack():
    knowledge = ATTACKKnowledgeService()
    cases = load_cases()
    assert len(cases) == 12 and len({c["id"] for c in cases}) == 12
    for case in cases:
        for technique in case["expected_techniques"]:
            resolved = knowledge.resolve_technique(technique)
            assert resolved and not resolved.deprecated, (case["id"], technique)
        assert set(case["expected_order"]) <= set(case["expected_techniques"])


def test_scoring():
    case = {"expected_techniques": ["T1566.001", "T1059.001", "T1486"], "expected_order": ["T1566.001", "T1059.001", "T1486"]}
    perfect = score(case, cir_for(["T1566.001", "T1059.001", "T1486"]))
    assert perfect["exact"]["f1"] == 1.0 and perfect["ordering"] == 1.0
    partial = score(case, cir_for(["T1059", "T1566.001", "T1490"]))
    assert partial["exact"] == {"precision": 0.3333, "recall": 0.3333, "f1": 0.3333}
    assert partial["parent"]["recall"] == pytest.approx(0.6667, abs=1e-4)  # T1059 matches T1059.001 at parent level
    assert partial["missing"] == ["T1059.001", "T1486"] and partial["extra"] == ["T1059", "T1490"]
    assert ordering_accuracy(["A", "B", "C"], ["B", "A", "C"]) == 0.5
    assert score(case, None)["exact"]["f1"] == 0.0


@pytest.fixture()
def two_models(monkeypatch):
    profiles = [{"name": "good-model", "model": "m1", "mode": "tools"}, {"name": "weak-model", "model": "m2", "mode": "json"}]
    monkeypatch.setattr(config.settings, "LLM_PROFILES", json.dumps(profiles))
    llm_client.profiles.cache_clear()
    truth = {c["narrative"]: c["expected_techniques"] for c in load_cases()}

    async def fake(text, *, repair=None, profile=None, instructions=None):
        if profile == "good-model":
            return cir_for(truth[text])
        return cir_for(truth[text][:1])  # the weak model only finds the first step

    monkeypatch.setattr(llm_parser, "parse_narrative_to_cir", fake)
    yield
    llm_client.profiles.cache_clear()


def test_benchmark_run_compares_models(api_client, make_user, two_models):
    user = make_user("researcher")
    assert len(api_client.get("/api/v1/benchmark/cases", headers=user).json()) == 12
    started = api_client.post("/api/v1/benchmark/runs", json={"profiles": ["good-model", "weak-model"],
                                                               "case_ids": ["web-shell-exfiltration", "macos-infostealer"]}, headers=user)
    assert started.status_code == 202, started.text
    run = api_client.get(f"/api/v1/benchmark/runs/{started.json()['id']}", headers=user).json()
    assert run["status"] == "done", run
    good = run["report"]["profiles"]["good-model"]["summary"]
    weak = run["report"]["profiles"]["weak-model"]["summary"]
    assert good["cases"] == 2 and good["exact_f1"] == 1.0 and good["valid_rate"] == 1.0
    assert weak["exact_f1"] < good["exact_f1"] and weak["exact_recall"] < 0.5
    listed = api_client.get("/api/v1/benchmark/runs", headers=user).json()
    assert listed[0]["summary"]["good-model"]["exact_f1"] == 1.0

    other = make_user("other")
    assert api_client.get(f"/api/v1/benchmark/runs/{run['id']}", headers=other).status_code == 404
    assert api_client.get("/api/v1/benchmark/runs", headers=other).json() == []


def test_benchmark_input_validation(api_client, make_user, two_models):
    user = make_user("researcher")
    assert api_client.post("/api/v1/benchmark/runs", json={"profiles": ["nope"]}, headers=user).status_code == 400
    assert api_client.post("/api/v1/benchmark/runs", json={"profiles": ["good-model"], "case_ids": ["x"]}, headers=user).status_code == 400
    assert api_client.post("/api/v1/benchmark/runs", json={"profiles": []}, headers=user).status_code == 422


def test_only_one_active_run(api_client, make_user, two_models, db_engine):
    from sqlalchemy.orm import Session

    from app.models.benchmark_run import BenchmarkRun
    from app.models.user import UserRecord

    user = make_user("researcher")
    with Session(db_engine) as session:
        owner_id = session.query(UserRecord).filter(UserRecord.username == "researcher").one().id
        session.add(BenchmarkRun(owner_id=owner_id, status="running", profiles=["good-model"]))
        session.commit()
    assert api_client.post("/api/v1/benchmark/runs", json={"profiles": ["good-model"]}, headers=user).status_code == 409
