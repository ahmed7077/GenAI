import csv
import io
import json
from datetime import UTC, datetime
from ipaddress import ip_address
from typing import Any

from pydantic import BaseModel, Field, field_validator


class NormalizedEvent(BaseModel):
    event_type: str = Field(min_length=1, max_length=120)
    occurred_at: datetime
    source_ip: str | None = None
    host: str | None = Field(default=None, max_length=255)
    actor: str | None = Field(default=None, max_length=255)
    outcome: str | None = Field(default=None, max_length=40)
    raw_event: dict[str, Any]

    @field_validator("source_ip")
    @classmethod
    def validate_ip(cls, value: str | None) -> str | None:
        if value:
            ip_address(value)
        return value


def normalize_event(payload: dict[str, Any]) -> NormalizedEvent:
    timestamp = payload.get("occurred_at") or payload.get("timestamp") or payload.get("time")
    if not timestamp:
        raise ValueError("Event timestamp is required")
    occurred_at = datetime.fromisoformat(str(timestamp).replace("Z", "+00:00"))
    if occurred_at.tzinfo is None:
        occurred_at = occurred_at.replace(tzinfo=UTC)
    return NormalizedEvent(
        event_type=str(payload.get("event_type") or payload.get("type") or "unknown"),
        occurred_at=occurred_at,
        source_ip=payload.get("source_ip") or payload.get("src_ip"),
        host=payload.get("host") or payload.get("hostname"),
        actor=payload.get("actor") or payload.get("user"),
        outcome=payload.get("outcome") or payload.get("status"),
        raw_event=payload,
    )


def parse_events(content: bytes, content_type: str) -> list[NormalizedEvent]:
    if len(content) > 10 * 1024 * 1024:
        raise ValueError("Upload exceeds 10 MiB limit")
    text = content.decode("utf-8")
    if content_type == "application/json":
        payload = json.loads(text)
        records = payload if isinstance(payload, list) else [payload]
    elif content_type in {"text/csv", "application/csv"}:
        records = list(csv.DictReader(io.StringIO(text)))
    else:
        raise ValueError("Only JSON and CSV event uploads are supported")
    return [normalize_event(record) for record in records]
