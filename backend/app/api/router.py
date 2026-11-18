from fastapi import APIRouter

from app.api.auth import router as auth_router
from app.api.detection import router as detection_router
from app.api.events import router as events_router

router = APIRouter()
router.include_router(auth_router)
router.include_router(events_router)
router.include_router(detection_router)


@router.get("/health", tags=["system"])
def health_check() -> dict[str, str]:
    return {"status": "ok"}

