from uuid import UUID

from fastapi import APIRouter, Depends, File, HTTPException, Query, UploadFile, status
from pydantic import BaseModel
from sqlalchemy import func, or_, select
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


class EventPage(BaseModel):
    items: list[EventResponse]
    total: int
    page: int
    categories: list[str]


@router.get("/page")
def event_page(
    page: int = Query(1, ge=1),
    query: str = Query("", max_length=255),
    category: str = Query("", max_length=120),
    user: User = Depends(get_current_user),
    session: Session = Depends(get_session),
) -> EventPage:
    filters = []
    if category:
        filters.append(or_(SecurityEvent.event_type == category, SecurityEvent.event_type.startswith(category + ".", autoescape=True)))
    if query.strip():
        search = query.strip().lower()
        try:
            event_id = UUID(search)
        except ValueError:
            event_id = None
        filters.append(or_(SecurityEvent.id == event_id, *(func.lower(column).contains(search, autoescape=True) for column in (
            SecurityEvent.event_type, SecurityEvent.actor, SecurityEvent.source_ip, SecurityEvent.host, SecurityEvent.outcome,
        ))))
    total = session.scalar(select(func.count()).select_from(SecurityEvent).where(*filters)) or 0
    page = min(page, max(1, (total + 49) // 50))
    records = session.scalars(
        select(SecurityEvent).where(*filters)
        .order_by(SecurityEvent.occurred_at.desc(), SecurityEvent.id.desc())
        .offset((page - 1) * 50).limit(50)
    )
    types = session.scalars(select(SecurityEvent.event_type).distinct())
    return EventPage(
        items=[EventResponse(id=row.id, event_type=row.event_type, occurred_at=row.occurred_at.isoformat(),
                             source_ip=row.source_ip, host=row.host, actor=row.actor, outcome=row.outcome) for row in records],
        total=total, page=page, categories=sorted({value.split(".", 1)[0] for value in types}),
    )


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
    limit: int = 10000, user: User = Depends(get_current_user), session: Session = Depends(get_session)
) -> list[EventResponse]:
    records = session.scalars(select(SecurityEvent).order_by(SecurityEvent.occurred_at.desc()).limit(min(limit, 10000))).all()
    return [EventResponse(id=row.id, event_type=row.event_type, occurred_at=row.occurred_at.isoformat(), source_ip=row.source_ip, host=row.host, actor=row.actor, outcome=row.outcome) for row in records]


@router.get("/summary")
async def event_summary(user: User = Depends(get_current_user), session: Session = Depends(get_session)) -> dict[str, int]:
    return {"events": session.scalar(select(func.count()).select_from(SecurityEvent)) or 0}
