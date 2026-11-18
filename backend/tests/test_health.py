from app.api.router import health_check


def test_health_check_reports_ready() -> None:
    response = health_check()

    assert response == {"status": "ok"}

