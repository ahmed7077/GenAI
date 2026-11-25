from functools import lru_cache
from typing import Literal

from pydantic import model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    threatlens_environment: Literal["development", "production"] = "development"
    threatlens_demo_mode: bool = False
    app_name: str = "ThreatLens API"
    api_v1_prefix: str = "/api/v1"
    database_url: str = "sqlite:///./threatlens.db"
    cors_origins: str = "http://localhost:5173"
    jwt_secret: str = "development-only-change-me"
    jwt_algorithm: str = "HS256"
    access_token_minutes: int = 480
    gemini_api_key: str | None = None
    gemini_model: str = "gemini-3.5-flash"
    gemini_fallback_models: str = "gemini-3.5-flash-lite,gemini-3.8-flash,gemini-flash-latest"
    ai_model_timeout_seconds: int = 15
    model_dir: str = "models"

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    @model_validator(mode="after")
    def validate_production(self) -> "Settings":
        if self.threatlens_environment != "production":
            return self
        if self.threatlens_demo_mode:
            raise ValueError("Production requires THREATLENS_DEMO_MODE=false")
        if len(self.jwt_secret) < 32 or self.jwt_secret == "development-only-change-me":
            raise ValueError("Production requires a JWT secret of at least 32 characters")
        if not self.database_url.startswith(("postgresql://", "postgresql+psycopg://")):
            raise ValueError("Production requires PostgreSQL")
        if any(not origin.strip().startswith("https://") for origin in self.cors_origins.split(",")):
            raise ValueError("Production requires explicit HTTPS CORS origins")
        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()

