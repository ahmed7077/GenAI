from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.auth import get_current_user, get_session
from app.models import AuditRecord, Incident, IncidentStatus, User

router = APIRouter(prefix="/incidents", tags=["incidents"])


class IncidentCreate(BaseModel):
    title: str = Field(min_length=3, max_length=255)
    severity: str = Field(pattern="^(critical|high|medium|low)$")
    confidence: int = Field(ge=0, le=100)
    evidence: dict[str, object]


@router.get("")
async def list_incidents(user: User = Depends(get_current_user), session: Session = Depends(get_session)) -> list[Incident]:
    return list(session.scalars(select(Incident).order_by(Incident.created_at.desc())).all())


@router.post("", status_code=status.HTTP_201_CREATED)
async def create_incident(payload: IncidentCreate, user: User = Depends(get_current_user), session: Session = Depends(get_session)) -> Incident:
    incident = Incident(**payload.model_dump(), created_by=user.id)
    session.add(incident)
    session.flush()
    session.add(AuditRecord(actor_id=user.id, action="incident.created", target_type="incident", target_id=str(incident.id)))
    session.commit()
    session.refresh(incident)
    return incident


@router.patch("/{incident_id}/status")
async def update_status(incident_id: UUID, status_value: IncidentStatus, user: User = Depends(get_current_user), session: Session = Depends(get_session)) -> Incident:
    incident = session.get(Incident, incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    incident.status = status_value
    session.add(AuditRecord(actor_id=user.id, action="incident.status_changed", target_type="incident", target_id=str(incident.id), detail=status_value.value))
    session.commit()
    session.refresh(incident)
    return incident
