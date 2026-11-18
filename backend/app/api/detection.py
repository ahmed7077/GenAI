from collections import Counter

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.auth import get_current_user, get_session
from app.models import SecurityEvent, User

router = APIRouter(prefix="/detection", tags=["detection"])

REVIEW_EVENT_TYPES = {
    "repo.set_workflow_permission_can_approve_pr": "Workflow approvals changed",
    "repo.set_default_workflow_permissions": "Default workflow permissions changed",
    "repo.change_merge_setting": "Repository merge settings changed",
    "oauth_access.create": "OAuth access created",
    "oauth_access.regenerate": "OAuth access regenerated",
    "oauth_access.destroy": "OAuth access revoked",
}


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
    review_signals = [
        {
            "event_id": str(event.id),
            "event_type": event.event_type,
            "label": REVIEW_EVENT_TYPES[event.event_type],
            "occurred_at": event.occurred_at.isoformat(),
            "actor": event.actor,
        }
        for event in reversed(events)
        if event.event_type in REVIEW_EVENT_TYPES
    ][:20]
    return {
        "incident_candidates": evidence,
        "review_signals": review_signals,
        "evaluated_events": len(events),
        "rule": "three failed logins followed by success from same source",
        "review_rule": "configuration and OAuth changes are review signals, not confirmed incidents",
    }
