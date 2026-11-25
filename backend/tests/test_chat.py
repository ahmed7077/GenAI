from app.api.chat import ChatTurn, evidence_terms


def test_follow_up_retains_previous_user_event_type():
    history = [
        ChatTurn(role="user", text="Review login.failed"),
        ChatTurn(role="assistant", text="oauth_access.regenerate"),
    ]
    terms = evidence_terms("Which should I review?", history)
    assert "login.failed" in terms
    assert "oauth_access.regenerate" not in terms
