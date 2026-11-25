from datetime import datetime, timedelta
from uuid import uuid4

from app.api.detection import correlate_authentication
from app.models import SecurityEvent


def test_authentication_requires_prior_failures_within_window():
    start = datetime(2026, 1, 1)

    def event(kind, minute):
        return SecurityEvent(
            id=uuid4(), event_type=f"login.{kind}", source_ip="192.0.2.1",
            occurred_at=start + timedelta(minutes=minute),
        )

    failures = [event("failed", minute) for minute in (1, 2, 3)]
    success = event("success", 4)
    assert not correlate_authentication([event("success", 0), *failures])
    assert not correlate_authentication([*failures, event("success", 20)])
    result = correlate_authentication([success, *failures])
    assert result[0]["success_event_id"] == str(success.id)
    assert result[0]["failure_event_ids"] == [str(item.id) for item in failures]
