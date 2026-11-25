import asyncio

from app.api.chat import ChatRequest, ChatTurn, GeminiProvider, evidence_terms, investigation


def test_follow_up_retains_previous_user_event_type():
    history = [
        ChatTurn(role="user", text="Review login.failed"),
        ChatTurn(role="assistant", text="oauth_access.regenerate"),
    ]
    terms = evidence_terms("Which should I review?", history)
    assert "login.failed" in terms
    assert "oauth_access.regenerate" not in terms


def test_investigation_graph_executes_all_five_stages(monkeypatch):
    class EmptySession:
        def scalars(self, statement):
            return []

    monkeypatch.setattr(GeminiProvider, "models", lambda self: ["test-model"])
    monkeypatch.setattr(GeminiProvider, "generate", lambda *args: "Review available evidence.")

    async def run():
        return [stage async for stage in investigation.astream(
            {"payload": ChatRequest(question="T1110"), "session": EmptySession()},
            stream_mode="updates",
        )]

    stages = asyncio.run(run())
    assert [next(iter(stage)) for stage in stages] == [
        "Triage", "Evidence collection", "Correlation", "Reference retrieval", "Response synthesis",
    ]
    assert stages[-1]["Response synthesis"]["response"]["sources"][0]["id"] == "mitre-t1110"
