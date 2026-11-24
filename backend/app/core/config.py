from __future__ import annotations

import logging
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

logger = logging.getLogger(__name__)

_INSECURE_DEFAULTS = {
    "CHANGE-THIS-IN-ENV-FILE-TO-A-LONG-RANDOM-STRING",
    "replace-with-a-long-random-value",
    "secret",
    "changeme",
    "",
}


ALLOWED_JWT_ALGORITHMS = frozenset({"HS256", "HS384", "HS512"})


class Settings(BaseSettings):
    PROJECT_NAME: str = "ThreatCanvas AI"
    ENVIRONMENT: str = "development"
    OPENAI_API_KEY: str = ""
    OPENAI_API_BASE: str = "https://ai.sumopod.com/v1"

    # --- LLM providers (any OpenAI-compatible API: OpenAI, Azure, SumoPod,
    # Ollama, vLLM, LM Studio, ...). Without LLM_PROFILES a single profile is
    # built from OPENAI_API_BASE / OPENAI_API_KEY / LLM_MODEL / LLM_MODE.
    LLM_MODEL: str = "gpt-4o"
    # "tools" = function calling; "json" = JSON mode (for models without
    # reliable tool calling, e.g. many local Ollama models)
    LLM_MODE: str = "tools"
    # JSON list of profiles, e.g.
    # [{"name":"gpt-4o","base_url":"https://api.openai.com/v1","api_key_env":"OPENAI_API_KEY","model":"gpt-4o","mode":"tools"},
    #  {"name":"llama3.1-local","base_url":"http://localhost:11434/v1","model":"llama3.1:8b","mode":"json"}]
    # api_key_env names an environment variable; keys never go in this JSON.
    LLM_PROFILES: str = ""
    LLM_DEFAULT_PROFILE: str = ""
    LLM_TIMEOUT_SECONDS: float = 90.0
    DATABASE_URL: str = "sqlite:///./threatcanvas.db"

    SECRET_KEY: str = "CHANGE-THIS-IN-ENV-FILE-TO-A-LONG-RANDOM-STRING"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24  # 1 hari

    # Set ke false untuk menonaktifkan endpoint /api/v1/auth/register.
    # Di produksi, daftarkan user pertama lalu matikan registrasi terbuka.
    ALLOW_REGISTRATION: bool = True

    # Self-repair: how many times a CIR that fails validation is sent back to
    # the LLM with its errors before /parse gives up (0 disables repair).
    LLM_REPAIR_ATTEMPTS: int = Field(default=2, ge=0, le=5)

    # Username that adopts scenarios created before per-user ownership existed.
    # Empty = adopt automatically only when exactly one user exists.
    LEGACY_SCENARIO_OWNER: str = ""

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    def validate_security(self) -> None:
        """Dipanggil saat startup — crash early jika konfigurasi tidak aman."""
        # Token ditandatangani dengan SECRET_KEY simetris: hanya HMAC yang valid.
        # Mencegah ALGORITHM di-set ke "none" atau algoritma asimetris.
        if self.ALGORITHM not in ALLOWED_JWT_ALGORITHMS:
            raise RuntimeError(
                f"ALGORITHM={self.ALGORITHM!r} tidak didukung; gunakan salah satu dari "
                f"{sorted(ALLOWED_JWT_ALGORITHMS)}."
            )
        if self.ENVIRONMENT == "test":
            return
            
        if self.SECRET_KEY.strip() in _INSECURE_DEFAULTS or len(self.SECRET_KEY) < 32:
            raise RuntimeError(
                "SECRET_KEY tidak aman: set nilai acak ≥32 karakter di file .env.\n"
                "Generate: python -c \"import secrets; print(secrets.token_urlsafe(32))\""
            )
        if self.ENVIRONMENT == "production" and self.ALLOW_REGISTRATION:
            logger.warning(
                "ALLOW_REGISTRATION=true di environment production. "
                "Pertimbangkan mematikannya setelah user pertama dibuat."
            )


settings = Settings()
