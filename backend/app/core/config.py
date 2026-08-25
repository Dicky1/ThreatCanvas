from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    PROJECT_NAME: str = "ThreatCanvas AI"
    ENVIRONMENT: str = "development"
    OPENAI_API_KEY: str = ""
    OPENAI_API_BASE: str = "https://ai.sumopod.com/v1"
    DATABASE_URL: str = "sqlite:///./threatcanvas.db"
    REDIS_URL: str = "redis://localhost:6379/0"

    SECRET_KEY: str = "CHANGE-THIS-IN-ENV-FILE-TO-A-LONG-RANDOM-STRING"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24  # 1 hari

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")


settings = Settings()
