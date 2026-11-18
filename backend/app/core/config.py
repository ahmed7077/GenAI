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

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")


@lru_cache
def get_settings() -> Settings:
    return Settings()

