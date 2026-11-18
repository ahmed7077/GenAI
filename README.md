# ThreatLens

ThreatLens is an evidence-first, defensive security intelligence and incident investigation platform. This repository currently contains the Phase 1 foundation: a FastAPI service, a React/Vite web shell, PostgreSQL Docker Compose configuration, initial CI, and a tested health endpoint.

## Run locally

1. Copy `.env.example` to `.env` and replace all deployment secrets.
2. Run `docker compose up --build`.
3. Open `http://localhost:5173`; API health is at `http://localhost:8000/api/v1/health`.

## Validate

- `cd backend && pip install -e ".[dev]" && python -m ruff check app tests && python -m pytest`
- `cd frontend && npm install && npm run build`

## Status

See `docs/DEVELOPMENT_PROGRESS.md`. Feature documentation is added only when the corresponding capability is implemented.

