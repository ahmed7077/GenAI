from app.rag import retrieve


def test_retrieval_returns_verifiable_official_sources() -> None:
    sources = retrieve("repeated authentication failures and a successful login")

    assert sources
    assert all(str(source["url"]).startswith("https://") for source in sources)
    assert any(source["id"] == "mitre-t1110" for source in sources)
