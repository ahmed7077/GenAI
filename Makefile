.PHONY: api-test web-test web-build up

api-test:
	cd backend && python -m pytest

web-test:
	cd frontend && npm test -- --run

web-build:
	cd frontend && npm run build

up:
	docker compose up --build

