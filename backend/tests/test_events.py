import pytest

from app.events import parse_events


def test_json_events_are_normalized_with_original_evidence() -> None:
    events = parse_events(b'[{"timestamp":"2026-11-18T10:00:00Z","type":"login.failed","src_ip":"192.0.2.1"}]', "application/json")

    assert events[0].event_type == "login.failed"
    assert events[0].raw_event["src_ip"] == "192.0.2.1"


def test_event_parser_rejects_unsupported_content() -> None:
    with pytest.raises(ValueError, match="Only JSON"):
        parse_events(b"not an event", "text/plain")


def test_github_security_log_epoch_is_normalized() -> None:
    events = parse_events(b'created_at,action,actor\n1429548104000,repo.create,octocat\n', "text/csv")

    assert events[0].event_type == "repo.create"
    assert events[0].actor == "octocat"
