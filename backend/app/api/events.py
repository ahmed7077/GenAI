from uuid import UUID

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile, status
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.auth import get_current_user, get_session
from app.events import parse_events
from app.models import AuditRecord, SecurityEvent, User

router = APIRouter(prefix="/events", tags=["events"])


class EventResponse(BaseModel):
    id: UUID
    event_type: str
    occurred_at: str
    source_ip: str | None
    host: str | None
    actor: str | None
    outcome: str | None


@router.post("/upload", status_code=status.HTTP_201_CREATED)
async def upload_events(
    file: UploadFile = File(...), user: User = Depends(get_current_user), session: Session = Depends(get_session)
) -> dict[str, int]:
    try:
        records = parse_events(await file.read(), file.content_type or "", file.filename or "")
    except (UnicodeDecodeError, ValueError) as error:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(error)) from error
    for record in records:
        session.add(SecurityEvent(**record.model_dump(), ingested_by=user.id))
    session.add(AuditRecord(actor_id=user.id, action="events.uploaded", target_type="upload", detail=file.filename or ""))
    session.commit()
    return {"ingested": len(records)}


@router.get("", response_model=list[EventResponse])
async def list_events(
    limit: int = 2000, user: User = Depends(get_current_user), session: Session = Depends(get_session)
) -> list[EventResponse]:
    records = session.scalars(select(SecurityEvent).order_by(SecurityEvent.occurred_at.desc()).limit(min(limit, 2000))).all()
    return [EventResponse(id=row.id, event_type=row.event_type, occurred_at=row.occurred_at.isoformat(), source_ip=row.source_ip, host=row.host, actor=row.actor, outcome=row.outcome) for row in records]


@router.get("/summary")
async def event_summary(user: User = Depends(get_current_user), session: Session = Depends(get_session)) -> dict[str, int]:
    return {"events": session.scalar(select(func.count()).select_from(SecurityEvent)) or 0}
