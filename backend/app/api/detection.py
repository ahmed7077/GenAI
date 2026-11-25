from collections import defaultdict
from datetime import timedelta

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


def correlate_authentication(events: list[SecurityEvent]) -> list[dict[str, object]]:
    pending: dict[str, list[SecurityEvent]] = defaultdict(list)
    candidates: dict[str, dict[str, object]] = {}
    for event in sorted(events, key=lambda item: item.occurred_at):
        source = event.source_ip
        if not source:
            continue
        if event.event_type == "login.failed":
            pending[source].append(event)
        elif event.event_type == "login.success":
            cutoff = event.occurred_at - timedelta(minutes=15)
            related = [item for item in pending.pop(source, []) if cutoff <= item.occurred_at < event.occurred_at]
            if len(related) >= 3:
                candidates[source] = {
                    "source_ip": source,
                    "failed_logins": len(related),
                    "failure_event_ids": [str(item.id) for item in related],
                    "success_event_id": str(event.id),
                }
    return list(candidates.values())


@router.get("/evaluate")
async def evaluate(user: User = Depends(get_current_user), session: Session = Depends(get_session)) -> dict[str, object]:
    events = list(session.scalars(select(SecurityEvent).order_by(SecurityEvent.occurred_at)))
    evidence = correlate_authentication(events)
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
        "rule": "three failed logins followed within 15 minutes by success from the same source",
        "review_rule": "configuration and OAuth changes are review signals, not confirmed incidents",
    }
