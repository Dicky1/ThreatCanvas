from __future__ import annotations

import logging
from pydantic_settings import BaseSettings, SettingsConfigDict

logger = logging.getLogger(__name__)

_INSECURE_DEFAULTS = {
    "CHANGE-THIS-IN-ENV-FILE-TO-A-LONG-RANDOM-STRING",
    "replace-with-a-long-random-value",
    "secret",
    "changeme",
    "",
}


class Settings(BaseSettings):
    PROJECT_NAME: str = "ThreatCanvas AI"
    ENVIRONMENT: str = "development"
    OPENAI_API_KEY: str = ""
    OPENAI_API_BASE: str = "https://ai.sumopod.com/v1"
    DATABASE_URL: str = "sqlite:///./threatcanvas.db"

    SECRET_KEY: str = "CHANGE-THIS-IN-ENV-FILE-TO-A-LONG-RANDOM-STRING"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24  # 1 hari

    # Set ke false untuk menonaktifkan endpoint /api/v1/auth/register.
    # Di produksi, daftarkan user pertama lalu matikan registrasi terbuka.
    ALLOW_REGISTRATION: bool = True

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    def validate_security(self) -> None:
        """Dipanggil saat startup — crash early jika konfigurasi tidak aman."""
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
