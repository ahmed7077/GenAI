# Development Progress

## Phase 1 — Foundation

- [x] Empty GitHub repository inspected and local main branch connected; foundation pushed as `8c1e7ee`.
- [x] Modular monolith foundation created: FastAPI API, React/Vite web client, PostgreSQL Compose service, environment template, CI, and health test.
- [x] Validation completed: API linting and health test pass; frontend production build passes.
- [ ] Commit, push, and verify the foundation.

## Phase 2 — Identity and audit foundation

- [x] Added SQLAlchemy user and immutable audit-record models, Alembic baseline migration, Argon2id password hashing, signed JWT tokens, and role enforcement helpers.
- [x] Added registration and login API routes with audited account actions.
- [x] Added unit tests for password verification and tamper-resistant token decoding.
- [x] Validation completed: backend lint, three unit tests, and `alembic upgrade head` pass against the local SQLite development configuration.
- [ ] Commit, push, and verify this feature.

## Phase 3 — Event ingestion

- [x] Added a safe JSON/CSV parser with 10 MiB upload cap, UTF-8 decoding, IP validation, timestamp normalization, and preserved raw evidence.
- [x] Added a persistent security-event model and parser unit tests.
- [x] Validation completed: backend lint and five unit tests pass. Packaging discovery now explicitly includes only the API package.
- [ ] Commit, push, and verify this feature.

## External dependencies

- A Gemini API key is optional until AI-provider integration is implemented.
- CICIDS2017 raw data is not bundled. Later phases will use synthetic test fixtures and document full-data acquisition.
- `npm audit` could not reach the npm audit endpoint in this execution environment; no clean audit result is claimed.

## Phase 4 — Interactive workflows and applied ML

- [x] Added Playwright browser coverage for Evidence Vault and Model Intelligence navigation, plus checklist submission using a controlled assistant response. With the demo running, run `npx playwright test e2e/demo.spec.ts` from `frontend` after installing Chromium, or set `THREATLENS_BROWSER_CHANNEL=msedge` to use installed Edge.

- [x] Added `scripts/check-demo.ps1` to smoke-test the local demo web shell, evidence inventory, detection evidence trail, model status, and case list.

- [x] Authentication correlation now requires prior failures within 15 minutes of a success from the same source and exposes the matching event IDs for review.

- [x] Added a print layout for analyst case reports with case metadata, attached evidence, and the latest audit timeline. Use the browser’s Save as PDF destination.

- [x] Added the Analyst Cases tab for creating cases, setting review status, adding notes, and viewing the audit timeline.

- [x] Added incident review notes and an audit timeline API. Case edits require an analyst or administrator role.

- [x] Added incident-brief and review-checklist modes to the Investigation Assistant, with evidence references in the local fallback.

- [x] Investigation chat sends up to six previous turns, ranks stored events by matching event type and recency, and returns evidence IDs alongside retrieved guidance. The local retrieval fallback adapts its review advice to the evidence selected.

- [x] Local Docker Compose opens a shared demo dashboard without sign-in and binds published ports to loopback. Set `THREATLENS_DEMO_MODE=false` in `.env` and rebuild to restore sign-in.

- [x] Return analysts to sign-in with an explanation when the API rejects the saved workspace session.

- [x] Replaced visual-only navigation with separate dashboard, evidence explorer, authentication detection, model intelligence, and evidence-bounded investigation views.
- [x] Mounted locally trained CICIDS2017 artifacts read-only into the API and added authenticated model-status and complete-flow inference endpoints.
- [x] Kept model applicability explicit: CICIDS2017 network-flow models are not applied to GitHub audit or host-authentication records, which continue through their schema-aware parser and correlation detector.
- [x] Validated the rebuilt Compose stack, health endpoint, authenticated model status, and mounted artifact metadata (400,000 sampled training records and 78 features).
- [x] Added a bounded 30-second AI-provider timeout so unavailable model requests return a clear API error instead of leaving the investigation interface waiting indefinitely.
- [x] Redesigned the SOC workspace with an earthy visual system, hover-reveal navigation, in-rail sign-out, responsive layouts, motion, evidence-derived event distribution chart, and a threaded investigation conversation interface.
- [x] Corrected event retrieval so the dashboard reflects the database-backed stored-evidence total rather than a client retrieval window; interactive views now load up to 10,000 recent records while retaining the true total separately.
- [x] Added local cybersecurity RAG retrieval with curated NIST and MITRE sources, query-time relevance scoring, returned citation metadata, and retrieval unit coverage.
- [x] Added bounded Gemini model failover and a clearly labelled local RAG fallback so investigation responses remain available during provider capacity failures.
- [x] Evidence Vault search and event-family filtering query the complete database inventory and return 50 records per page with stable ordering.
- [x] Replaced the opaque percentage donut with a readable event-family bar chart; removed the duplicate live-evidence badge.
- [x] Added an explicitly non-incident GitHub/OAuth control-change review queue alongside the existing authentication-correlation detector, and made returned assistant citations clickable.

