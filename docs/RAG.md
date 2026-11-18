# ThreatLens cybersecurity RAG

ThreatLens performs retrieval locally before each investigation request. The corpus is curated, versioned in source control, and deliberately separate from uploaded logs: logs are untrusted evidence, not knowledge-base instructions.

## Included authoritative sources

- [NIST SP 800-61r3](https://csrc.nist.gov/pubs/sp/800/61/r3/final) — incident response recommendations.
- [MITRE ATT&CK T1078](https://attack.mitre.org/techniques/T1078/) — Valid Accounts.
- [MITRE ATT&CK T1110](https://attack.mitre.org/techniques/T1110/) — Brute Force.

The API uses TF-IDF plus cosine similarity to retrieve the most relevant sources, sends their excerpts and URLs to the configured Gemini provider alongside a bounded set of event summaries, and returns the selected source metadata with the answer. The assistant also appends the retrieved source titles and URLs to a successful response.

RAG sources are contextual guidance, not proof that a technique occurred in an uploaded log. An answer must distinguish retrieved guidance from event evidence and uncertainty.

## Provider resilience

The configured primary Gemini model is attempted first. On a provider failure or a 6-second attempt timeout, ThreatLens tries the configured fallback models in order and adds a system note to the response naming the primary failure and selected fallback. If every configured model is unavailable, ThreatLens switches to a clearly labelled local RAG fallback that summarizes only the observed event types and retrieved citations; it does not claim a generative analysis or infer an incident.
