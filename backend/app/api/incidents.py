from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.auth import get_current_user, get_session, require_role
from app.models import AuditRecord, Incident, IncidentStatus, User, UserRole

router = APIRouter(prefix="/incidents", tags=["incidents"])
case_writer = require_role(UserRole.ADMIN, UserRole.ANALYST)


class ReviewNote(BaseModel):
    text: str = Field(min_length=1, max_length=4000)


@router.get("/{incident_id}/timeline", response_model=None)
def incident_timeline(
    incident_id: UUID,
    user: User = Depends(get_current_user),
    session: Session = Depends(get_session),
) -> list[AuditRecord]:
    if session.get(Incident, incident_id) is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    return list(session.scalars(
        select(AuditRecord)
        .where(AuditRecord.target_type == "incident", AuditRecord.target_id == str(incident_id))
        .order_by(AuditRecord.created_at, AuditRecord.id)
    ))


@router.post("/{incident_id}/notes", status_code=201, response_model=None)
def add_review_note(
    incident_id: UUID,
    payload: ReviewNote,
    user: User = Depends(case_writer),
    session: Session = Depends(get_session),
) -> AuditRecord:
    if session.get(Incident, incident_id) is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    note = payload.text.strip()
    if not note:
        raise HTTPException(status_code=422, detail="A review note cannot be blank")
    entry = AuditRecord(
        actor_id=user.id, action="incident.review_note", target_type="incident",
        target_id=str(incident_id), detail=note,
    )
    session.add(entry)
    session.commit()
    session.refresh(entry)
    return entry


class IncidentCreate(BaseModel):
    title: str = Field(min_length=3, max_length=255)
    severity: str = Field(pattern="^(critical|high|medium|low)$")
    confidence: int = Field(ge=0, le=100)
    evidence: dict[str, object]


@router.get("", response_model=None)
async def list_incidents(user: User = Depends(get_current_user), session: Session = Depends(get_session)) -> list[Incident]:
    return list(session.scalars(select(Incident).order_by(Incident.created_at.desc())).all())


@router.post("", status_code=status.HTTP_201_CREATED, response_model=None)
async def create_incident(payload: IncidentCreate, user: User = Depends(case_writer), session: Session = Depends(get_session)) -> Incident:
    incident = Incident(**payload.model_dump(), created_by=user.id)
    session.add(incident)
    session.flush()
    session.add(AuditRecord(actor_id=user.id, action="incident.created", target_type="incident", target_id=str(incident.id)))
    session.commit()
    session.refresh(incident)
    return incident


@router.patch("/{incident_id}/status", response_model=None)
async def update_status(incident_id: UUID, status_value: IncidentStatus, user: User = Depends(case_writer), session: Session = Depends(get_session)) -> Incident:
    incident = session.get(Incident, incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    incident.status = status_value
    session.add(AuditRecord(actor_id=user.id, action="incident.status_changed", target_type="incident", target_id=str(incident.id), detail=status_value.value))
    session.commit()
    session.refresh(incident)
    return incident
