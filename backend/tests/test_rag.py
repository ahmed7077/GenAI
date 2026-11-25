from app.rag import retrieve


def test_retrieval_returns_verifiable_official_sources() -> None:
    sources = retrieve("repeated authentication failures and a successful login")

    assert sources
    assert all(str(source["url"]).startswith("https://") for source in sources)
    assert any(source["id"] == "mitre-t1110" for source in sources)


def test_unrelated_queries_do_not_return_reference_links() -> None:
    assert retrieve("hello") == []
    assert retrieve("chocolate cake frosting") == []


def test_source_identifier_is_searchable() -> None:
    assert retrieve("T1110", limit=1)[0]["id"] == "mitre-t1110"
