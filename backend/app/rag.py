"""Small, local, evidence-safe cybersecurity RAG corpus and retriever."""

from dataclasses import dataclass
from functools import lru_cache

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity


@dataclass(frozen=True)
class KnowledgeSource:
    source_id: str
    title: str
    url: str
    text: str


SOURCES = (
    KnowledgeSource(
        "nist-sp-800-61r3",
        "NIST SP 800-61r3: Incident Response Recommendations",
        "https://csrc.nist.gov/pubs/sp/800/61/r3/final",
        "NIST recommends analyzing potentially adverse events, estimating their scope and impact, "
        "making log analysis available to authorized responders, integrating current threat intelligence, "
        "and declaring incidents when activity meets defined incident criteria.",
    ),
    KnowledgeSource(
        "mitre-t1078",
        "MITRE ATT&CK T1078: Valid Accounts",
        "https://attack.mitre.org/techniques/T1078/",
        "Adversaries may abuse existing credentials to gain or maintain access, evade controls, and reach "
        "restricted resources. Valid-account activity alone is not proof of compromise; it requires context "
        "such as account role, source, timing, device, and intended access.",
    ),
    KnowledgeSource(
        "mitre-t1110",
        "MITRE ATT&CK T1110: Brute Force",
        "https://attack.mitre.org/techniques/T1110/",
        "Brute force involves repeated attempts to guess credentials. Authentication failures can be benign or "
        "malicious, so analysts should correlate them with account, source, eventual success, and other evidence.",
    ),
)


@lru_cache
def _index() -> tuple[TfidfVectorizer, object]:
    vectorizer = TfidfVectorizer(stop_words="english", ngram_range=(1, 2))
    return vectorizer, vectorizer.fit_transform(f"{source.title} {source.text}" for source in SOURCES)


def retrieve(query: str, limit: int = 3) -> list[dict[str, str | float]]:
    """Return relevant curated sources, never content supplied by an uploaded log."""
    vectorizer, matrix = _index()
    scores = cosine_similarity(vectorizer.transform([query]), matrix).ravel()
    matches = ((index, score) for index, score in enumerate(scores) if score > 0)
    ranked = sorted(matches, key=lambda item: item[1], reverse=True)[:max(0, limit)]
    return [
        {
            "id": SOURCES[index].source_id,
            "title": SOURCES[index].title,
            "url": SOURCES[index].url,
            "excerpt": SOURCES[index].text,
            "relevance": round(float(score), 4),
        }
        for index, score in ranked
    ]
