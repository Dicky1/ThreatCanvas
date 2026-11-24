import asyncio
import json
from types import SimpleNamespace

import pytest

from app.api.endpoints import parser
from app.core import config
from app.schemas.cir import CIRSpecification
from app.services import llm_client, llm_parser

PROFILES = json.dumps([
    {"name": "gpt-4o", "base_url": "https://api.openai.com/v1", "api_key_env": "TC_TEST_OPENAI_KEY", "model": "gpt-4o", "mode": "tools"},
    {"name": "llama-local", "base_url": "http://localhost:11434/v1", "model": "llama3.1:8b", "mode": "json"},
])
CIR_JSON = json.dumps({"scenario_id": "p", "attack_graph": {"nodes": [{"step_id": "s1", "tactic": "TA0002", "technique": "T1059.001",
                       "target": "WS01", "action_type": "Execution", "evidence": [{"description": "ps"}]}], "edges": []}})


@pytest.fixture()
def configured(monkeypatch):
    monkeypatch.setattr(config.settings, "LLM_PROFILES", PROFILES)
    monkeypatch.setattr(config.settings, "LLM_DEFAULT_PROFILE", "")
    llm_client.profiles.cache_clear()
    yield
    llm_client.profiles.cache_clear()


@pytest.mark.parametrize("raw,message", [
    ("not json", "not valid JSON"),
    ("[]", "non-empty"),
    ('[{"name": "a b", "model": "m"}]', "name is invalid"),
    ('[{"name": "a", "model": "m", "api_key_env": "sk-123secret"}]', "environment variable name"),
    ('[{"name": "a", "model": "m", "base_url": "file:///x"}]', "http"),
    ('[{"name": "a", "model": "m", "mode": "magic"}]', "mode"),
    ('[{"name": "a", "model": "m"}, {"name": "a", "model": "n"}]', "unique"),
])
def test_malformed_profiles_fail_fast(monkeypatch, raw, message):
    monkeypatch.setattr(config.settings, "LLM_PROFILES", raw)
    llm_client.profiles.cache_clear()
    with pytest.raises(llm_client.LLMConfigError, match=message):
        llm_client.validate_configuration()
    llm_client.profiles.cache_clear()


def test_profiles_default_and_key_indirection(configured, monkeypatch):
    assert llm_client.default_profile().name == "gpt-4o"
    monkeypatch.setenv("TC_TEST_OPENAI_KEY", "sk-from-env")
    assert llm_client._api_key(llm_client.get_profile("gpt-4o")) == "sk-from-env"
    assert llm_client._api_key(llm_client.get_profile("llama-local")) == "not-needed"
    with pytest.raises(llm_client.UnknownProfileError):
        llm_client.get_profile("nope")
    assert llm_client.get_profile("llama-local").public() == {"name": "llama-local", "model": "llama3.1:8b", "mode": "json", "local": True}


class Recorder:
    def __init__(self, content=None, arguments=None):
        self.content, self.arguments, self.calls = content, arguments, []

    async def create(self, **kwargs):
        self.calls.append(kwargs)
        call = SimpleNamespace(function=SimpleNamespace(arguments=self.arguments))
        message = SimpleNamespace(content=self.content, tool_calls=[call] if self.arguments else None)
        return SimpleNamespace(choices=[SimpleNamespace(message=message)])


def run_with(monkeypatch, recorder, profile):
    monkeypatch.setattr(llm_parser, "client_for", lambda p: SimpleNamespace(chat=SimpleNamespace(completions=recorder)))
    return asyncio.run(llm_parser.parse_narrative_to_cir("x", profile=profile))


def test_json_mode_for_models_without_tool_calling(configured, monkeypatch):
    recorder = Recorder(content=f"```json\n{CIR_JSON}\n```")
    cir = run_with(monkeypatch, recorder, "llama-local")
    request = recorder.calls[0]
    assert cir.attack_graph.nodes[0].technique == "T1059.001"
    assert request["model"] == "llama3.1:8b" and request["response_format"] == {"type": "json_object"}
    assert "tools" not in request and "JSON Schema" in request["messages"][1]["content"]


def test_tools_mode_uses_profile_model(configured, monkeypatch):
    recorder = Recorder(arguments=CIR_JSON)
    run_with(monkeypatch, recorder, None)
    assert recorder.calls[0]["model"] == "gpt-4o" and recorder.calls[0]["tool_choice"]["function"]["name"] == "generate_cir"


def test_profiles_endpoint_and_parse_profile_selection(api_client, make_user, configured, monkeypatch):
    user = make_user("alice")
    body = api_client.get("/api/v1/llm/profiles", headers=user).json()
    assert body["default"] == "gpt-4o"
    assert "base_url" not in json.dumps(body) and "api_key" not in json.dumps(body)

    seen = []

    async def fake(text, *, repair=None, profile=None):
        seen.append(profile)
        return CIRSpecification(**json.loads(CIR_JSON))

    monkeypatch.setattr(parser, "parse_narrative_to_cir", fake)
    ok = api_client.post("/api/v1/parse", json={"scenario": "x", "model_profile": "llama-local"}, headers=user)
    assert ok.status_code == 200 and seen == ["llama-local"]
    bad = api_client.post("/api/v1/parse", json={"scenario": "x", "model_profile": "nope"}, headers=user)
    assert bad.status_code == 400 and seen == ["llama-local"]
