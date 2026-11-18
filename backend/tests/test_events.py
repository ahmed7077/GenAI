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


def test_github_audit_export_timestamp_and_ip_are_normalized() -> None:
    events = parse_events(b'@timestamp,action,actor,actor_ip\n1794996496521,user.audit_log_export,octocat,203.0.113.10\n', "text/csv")

    assert events[0].source_ip == "203.0.113.10"


def test_openssh_auth_log_is_normalized() -> None:
    events = parse_events(
        b"Jan 10 10:00:00 web-01 sshd[12]: Failed password for admin from 203.0.113.10 port 22 ssh2\n"
        b"Jan 10 10:03:00 web-01 sshd[15]: Accepted password for admin from 203.0.113.10 port 22 ssh2\n",
        "text/plain",
    )

    assert [event.event_type for event in events] == ["login.failed", "login.success"]
    assert events[0].source_ip == "203.0.113.10"
    assert events[1].host == "web-01"
