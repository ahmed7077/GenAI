from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "ThreatLens API"
    api_v1_prefix: str = "/api/v1"
    database_url: str = "sqlite:///./threatlens.db"
    cors_origins: str = "http://localhost:5173"
    jwt_secret: str = "development-only-change-me"
    jwt_algorithm: str = "HS256"
    access_token_minutes: int = 30
    gemini_api_key: str | None = None
    gemini_model: str = "gemini-3.5-flash"
    gemini_fallback_models: str = "gemini-3.5-flash-lite,gemini-3.8-flash,gemini-flash-latest"
    ai_model_timeout_seconds: int = 6
    model_dir: str = "models"

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")


@lru_cache
def get_settings() -> Settings:
    return Settings()

