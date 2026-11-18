import csv
import io
import json
import re
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
    timestamp = (
        payload.get("occurred_at")
        or payload.get("timestamp")
        or payload.get("@timestamp")
        or payload.get("time")
        or payload.get("created_at")
    )
    if not timestamp:
        raise ValueError("Event timestamp is required")
    if isinstance(timestamp, (int, float)) or str(timestamp).isdigit():
        occurred_at = datetime.fromtimestamp(int(timestamp) / 1000, tz=UTC)
    else:
        occurred_at = datetime.fromisoformat(str(timestamp).replace("Z", "+00:00"))
    if occurred_at.tzinfo is None:
        occurred_at = occurred_at.replace(tzinfo=UTC)
    return NormalizedEvent(
        event_type=str(payload.get("event_type") or payload.get("type") or payload.get("action") or "unknown"),
        occurred_at=occurred_at,
        source_ip=payload.get("source_ip") or payload.get("src_ip") or payload.get("actor_ip"),
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
    elif "sshd" in text and ("Failed password" in text or "Accepted " in text):
        return parse_openssh_auth_log(text)
    else:
        raise ValueError("Upload a JSON/CSV event export or an OpenSSH authentication log.")
    return [normalize_event(record) for record in records]


SSH_LINE = re.compile(
    r"^(?P<stamp>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+sshd(?:\[\d+\])?:\s+(?P<message>.+)$"
)
SSH_SOURCE = re.compile(r"\bfrom\s+(?P<ip>[0-9a-fA-F:.]+)")
SSH_ACCOUNT = re.compile(r"\bfor(?:\s+invalid\s+user)?\s+(?P<account>[^\s]+)")


def parse_openssh_auth_log(text: str) -> list[NormalizedEvent]:
    """Normalize conventional OpenSSH auth.log lines without fabricating fields."""
    current_year = datetime.now(UTC).year
    events: list[NormalizedEvent] = []
    for line in text.splitlines():
        match = SSH_LINE.match(line.strip())
        if not match:
            continue
        message = match["message"]
        if "Failed password" in message or "Invalid user" in message:
            event_type, outcome = "login.failed", "failure"
        elif "Accepted password" in message or "Accepted publickey" in message:
            event_type, outcome = "login.success", "success"
        else:
            continue
        source = SSH_SOURCE.search(message)
        account = SSH_ACCOUNT.search(message)
        occurred_at = datetime.strptime(match["stamp"], "%b %d %H:%M:%S").replace(year=current_year, tzinfo=UTC)
        events.append(
            NormalizedEvent(
                event_type=event_type,
                occurred_at=occurred_at,
                source_ip=source["ip"] if source else None,
                host=match["host"],
                actor=account["account"] if account else None,
                outcome=outcome,
                raw_event={"raw_line": line, "timestamp_year_inferred": current_year},
            )
        )
    if not events:
        raise ValueError("No supported OpenSSH failed or accepted login events were found.")
    return events
