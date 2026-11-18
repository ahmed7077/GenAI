from collections import Counter

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.auth import get_current_user, get_session
from app.models import SecurityEvent, User

router = APIRouter(prefix="/detection", tags=["detection"])


@router.get("/evaluate")
async def evaluate(user: User = Depends(get_current_user), session: Session = Depends(get_session)) -> dict[str, object]:
    events = session.scalars(select(SecurityEvent).order_by(SecurityEvent.occurred_at)).all()
    failures = Counter(event.source_ip for event in events if event.event_type == "login.failed" and event.source_ip)
    evidence = []
    for source, count in failures.items():
        related = [event for event in events if event.source_ip == source]
        names = {event.event_type for event in related}
        if count >= 3 and "login.success" in names:
            evidence.append({"source_ip": source, "failed_logins": count, "privilege_escalation": "privilege.escalation" in names, "sensitive_access": "file.read.sensitive" in names})
    return {"incident_candidates": evidence, "evaluated_events": len(events), "rule": "three failed logins followed by success from same source"}
