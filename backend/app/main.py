from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.router import router
from app.core.config import get_settings
from app.db import Base, engine
from app import models  # noqa: F401

settings = get_settings()
allowed_origins = [origin.strip() for origin in settings.cors_origins.split(",")]
if settings.threatlens_environment == "development" and "http://localhost:5173" in allowed_origins:
    allowed_origins.append("http://127.0.0.1:5173")
app = FastAPI(title=settings.app_name, version="0.1.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
    allow_headers=["Authorization", "Content-Type"],
)
app.include_router(router, prefix=settings.api_v1_prefix)


@app.on_event("startup")
async def create_database_tables() -> None:
    Base.metadata.create_all(bind=engine)

