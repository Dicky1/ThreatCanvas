"""Self-repair loop: CIRs that fail schema or validation are sent back to the
LLM with their errors (up to LLM_REPAIR_ATTEMPTS) before /parse gives up."""

import asyncio
import json
from types import SimpleNamespace

import pytest

from app.api.endpoints import parser
from app.core import config
from app.services import llm_parser
from app.services.llm_parser import CIRGenerationError, LLMUnavailableError, RepairContext


def cir(technique="T1059.001", tactic="TA0002"):
    return llm_parser.CIRSpecification(
        scenario_id="repair",
        attack_graph={
            "nodes": [{"step_id": "s1", "tactic": tactic, "technique": technique, "target": "WS01",
                       "action_type": "Execution", "evidence": [{"description": "PowerShell"}]}],
            "edges": [],
        },
    )


class FakeLLM:
    """Plays back a script of results/exceptions and records repair contexts."""

    def __init__(self, *script):
        self.script = list(script)
        self.repairs: list[RepairContext | None] = []

    async def __call__(self, narrative, *, repair=None):
        self.repairs.append(repair)
        item = self.script.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


@pytest.fixture()
def user(make_user):
    return make_user("analyst")


def parse(api_client, user):
    return api_client.post("/api/v1/parse", json={"scenario": "PowerShell then ransomware"}, headers=user)


def test_validation_failure_is_repaired(api_client, user, monkeypatch):
    fake = FakeLLM(cir(technique="T9999"), cir())
    monkeypatch.setattr(parser, "parse_narrative_to_cir", fake)
    response = parse(api_client, user)
    assert response.status_code == 200, response.text
    body = response.json()
    assert [a["stage"] for a in body["repair_attempts"]] == ["validation"]
    assert body["validation"]["valid"] and body["validation"]["errors"] == []
    assert fake.repairs[0] is None
    assert any("T9999" in error for error in fake.repairs[1].errors)
    assert '"T9999"' in fake.repairs[1].previous_output


def test_schema_failure_is_repaired(api_client, user, monkeypatch):
    fake = FakeLLM(CIRGenerationError(["attack_graph: Field required"], '{"scenario_id": "x"}'), cir())
    monkeypatch.setattr(parser, "parse_narrative_to_cir", fake)
    response = parse(api_client, user)
    assert response.status_code == 200, response.text
    assert response.json()["repair_attempts"][0] == {
        "attempt": 1, "stage": "schema", "errors": ["attack_graph: Field required"],
    }
    assert fake.repairs[1].previous_output == '{"scenario_id": "x"}'


def test_gives_up_after_configured_attempts(api_client, user, monkeypatch):
    monkeypatch.setattr(config.settings, "LLM_REPAIR_ATTEMPTS", 2)
    fake = FakeLLM(cir("T9999"), cir("T9998"), cir("T9997"), cir())
    monkeypatch.setattr(parser, "parse_narrative_to_cir", fake)
    response = parse(api_client, user)
    assert response.status_code == 400
    detail = response.json()["detail"]
    assert len(detail["repair_attempts"]) == 3
    assert len(fake.repairs) == 3  # 1 initial + 2 repairs, the 4th result is never requested
    assert api_client.get("/api/v1/scenarios", headers=user).json() == []


def test_repair_can_be_disabled(api_client, user, monkeypatch):
    monkeypatch.setattr(config.settings, "LLM_REPAIR_ATTEMPTS", 0)
    fake = FakeLLM(cir("T9999"), cir())
    monkeypatch.setattr(parser, "parse_narrative_to_cir", fake)
    assert parse(api_client, user).status_code == 400
    assert len(fake.repairs) == 1


def test_provider_outage_is_502_and_not_retried(api_client, user, monkeypatch):
    fake = FakeLLM(LLMUnavailableError("down"), cir())
    monkeypatch.setattr(parser, "parse_narrative_to_cir", fake)
    response = parse(api_client, user)
    assert response.status_code == 502
    assert "down" not in response.text
    assert len(fake.repairs) == 1


# --- llm_parser unit tests ----------------------------------------------------

class FakeCompletions:
    def __init__(self, arguments=None, error=None):
        self.arguments, self.error, self.calls = arguments, error, []

    async def create(self, **kwargs):
        self.calls.append(kwargs)
        if self.error:
            raise self.error
        call = SimpleNamespace(function=SimpleNamespace(arguments=self.arguments))
        return SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(tool_calls=[call]))])


def run(coro):
    return asyncio.run(coro)


def test_invalid_json_raises_generation_error(monkeypatch):
    monkeypatch.setattr(llm_parser.client.chat, "completions", FakeCompletions("{not json"))
    with pytest.raises(CIRGenerationError) as error:
        run(llm_parser.parse_narrative_to_cir("x"))
    assert error.value.raw_output == "{not json"


def test_schema_mismatch_lists_field_paths(monkeypatch):
    monkeypatch.setattr(llm_parser.client.chat, "completions", FakeCompletions(json.dumps({"scenario_id": "x"})))
    with pytest.raises(CIRGenerationError) as error:
        run(llm_parser.parse_narrative_to_cir("x"))
    assert any(e.startswith("attack_graph") for e in error.value.errors)


def test_provider_error_becomes_llm_unavailable(monkeypatch):
    monkeypatch.setattr(llm_parser.client.chat, "completions", FakeCompletions(error=RuntimeError("401 bad key")))
    with pytest.raises(LLMUnavailableError):
        run(llm_parser.parse_narrative_to_cir("x"))


def test_repair_context_is_sent_back_to_the_model(monkeypatch):
    completions = FakeCompletions(cir().model_dump_json())
    monkeypatch.setattr(llm_parser.client.chat, "completions", completions)
    run(llm_parser.parse_narrative_to_cir("narrative", repair=RepairContext("PREVIOUS", ["MITRE: Unknown T9999"])))
    messages = completions.calls[0]["messages"]
    assert [m["role"] for m in messages] == ["system", "user", "assistant", "user"]
    assert messages[2]["content"] == "PREVIOUS"
    assert "MITRE: Unknown T9999" in messages[3]["content"]
