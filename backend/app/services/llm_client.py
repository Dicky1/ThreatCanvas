"""Model-agnostic LLM access: named profiles for any OpenAI-compatible API
(OpenAI, Azure OpenAI, SumoPod, Ollama, vLLM, LM Studio, ...)."""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

from openai import AsyncOpenAI

from app.core.config import settings

NAME_RE = re.compile(r"^[\w.:@-]{1,64}$")
ENV_RE = re.compile(r"^[A-Z][A-Z0-9_]{0,63}$")
MODES = ("tools", "json")


class LLMConfigError(ValueError):
    """LLM_PROFILES is malformed (raised at startup)."""


class UnknownProfileError(ValueError):
    """A request asked for a profile that is not configured."""


@dataclass(frozen=True)
class LLMProfile:
    name: str
    model: str
    base_url: str | None
    api_key_env: str | None
    mode: str = "tools"

    def public(self) -> dict:
        """Safe to show to users: no URL, no key."""
        return {"name": self.name, "model": self.model, "mode": self.mode, "local": _is_local(self.base_url)}


def _is_local(base_url: str | None) -> bool:
    return bool(base_url) and bool(re.match(r"^https?://(localhost|127\.|0\.0\.0\.0|host\.docker\.internal|\[::1\])", base_url or ""))


def _validate(entry: dict, index: int) -> LLMProfile:
    if not isinstance(entry, dict):
        raise LLMConfigError(f"LLM_PROFILES[{index}] must be an object")
    name = str(entry.get("name") or "")
    model = str(entry.get("model") or "")
    base_url = entry.get("base_url") or None
    api_key_env = entry.get("api_key_env") or None
    mode = str(entry.get("mode") or "tools")
    if not NAME_RE.match(name):
        raise LLMConfigError(f"LLM_PROFILES[{index}].name is invalid")
    if not model or len(model) > 200:
        raise LLMConfigError(f"LLM_PROFILES[{index}].model is required")
    if base_url is not None and not re.match(r"^https?://", str(base_url)):
        raise LLMConfigError(f"LLM_PROFILES[{index}].base_url must be http(s)")
    if api_key_env is not None and not ENV_RE.match(str(api_key_env)):
        raise LLMConfigError(f"LLM_PROFILES[{index}].api_key_env must be an environment variable name")
    if mode not in MODES:
        raise LLMConfigError(f"LLM_PROFILES[{index}].mode must be one of {MODES}")
    return LLMProfile(name=name, model=model, base_url=base_url, api_key_env=api_key_env, mode=mode)


@lru_cache(maxsize=1)
def profiles() -> tuple[LLMProfile, ...]:
    if settings.LLM_PROFILES.strip():
        try:
            raw = json.loads(settings.LLM_PROFILES)
        except json.JSONDecodeError as error:
            raise LLMConfigError("LLM_PROFILES is not valid JSON") from error
        if not isinstance(raw, list) or not raw:
            raise LLMConfigError("LLM_PROFILES must be a non-empty JSON list")
        items = tuple(_validate(entry, index) for index, entry in enumerate(raw))
        names = [p.name for p in items]
        if len(names) != len(set(names)):
            raise LLMConfigError("LLM_PROFILES names must be unique")
        return items
    mode = settings.LLM_MODE if settings.LLM_MODE in MODES else "tools"
    return (LLMProfile(
        name=settings.LLM_MODEL,
        model=settings.LLM_MODEL,
        base_url=settings.OPENAI_API_BASE or None,
        api_key_env="OPENAI_API_KEY",
        mode=mode,
    ),)


def default_profile() -> LLMProfile:
    items = profiles()
    if settings.LLM_DEFAULT_PROFILE:
        for profile in items:
            if profile.name == settings.LLM_DEFAULT_PROFILE:
                return profile
        raise LLMConfigError("LLM_DEFAULT_PROFILE does not match any profile")
    return items[0]


def get_profile(name: str | None) -> LLMProfile:
    if not name:
        return default_profile()
    for profile in profiles():
        if profile.name == name:
            return profile
    raise UnknownProfileError(f"Unknown LLM profile: {name}")


def _api_key(profile: LLMProfile) -> str:
    if not profile.api_key_env:
        return "not-needed"  # e.g. Ollama ignores the key but the SDK requires one
    if profile.api_key_env == "OPENAI_API_KEY" and settings.OPENAI_API_KEY:
        return settings.OPENAI_API_KEY
    value = os.getenv(profile.api_key_env)
    if value is None and Path(".env").exists():
        from dotenv import dotenv_values

        value = dotenv_values(".env").get(profile.api_key_env)
    return value or "missing-api-key"


@lru_cache(maxsize=16)
def _client(name: str, base_url: str | None, api_key: str, timeout: float) -> AsyncOpenAI:
    return AsyncOpenAI(api_key=api_key, base_url=base_url, timeout=timeout, max_retries=1)


def client_for(profile: LLMProfile) -> AsyncOpenAI:
    return _client(profile.name, profile.base_url, _api_key(profile), settings.LLM_TIMEOUT_SECONDS)


def validate_configuration() -> None:
    """Called at startup so a broken LLM_PROFILES fails fast."""
    default_profile()
