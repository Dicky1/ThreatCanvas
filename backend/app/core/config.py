from pydantic_settings import BaseSettings, SettingsConfigDict
from typing import Optional

class Settings(BaseSettings):
    PROJECT_NAME: str = "ThreatCanvas AI"
    ENVIRONMENT: str = "development"
    OPENAI_API_KEY: str = "sk-h4Tp-PmJlyPOHzpG1c6jRA" # Masukkan key baru Anda
    OPENAI_API_BASE: str = "https://ai.sumopod.com/v1" # Tambahkan URL ini
    DATABASE_URL: str = "sqlite:///./threatcanvas.db" # Default fallback for local dev
    REDIS_URL: str = "redis://localhost:6379/0"

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

settings = Settings()