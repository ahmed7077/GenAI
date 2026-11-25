# ThreatLens

ThreatLens is a defensive security investigation workspace. It brings together searchable logs, rule-based detection, CICIDS2017 network-flow scoring, and an assistant that drafts evidence-grounded investigation summaries. The app uses React and TypeScript, FastAPI, and PostgreSQL.

## Run locally

1. Start Docker Desktop. From the repository root, copy `.env.example` to `.env` and configure any local overrides. Set `GEMINI_API_KEY` in `.env` to enable Gemini generation. The local retrieval fallback works without it.
2. Run `docker compose up -d --build`.
3. Open the [dashboard](http://localhost:5173) or [API documentation](http://localhost:8000/docs).

Compose defaults to a shared local demo with sign-in disabled and ports bound to loopback. Set `THREATLENS_DEMO_MODE=false` and rebuild to enable sign-in. Raw datasets, trained model artifacts, and credentials stay outside Git.

## Demo walkthrough

| Tab | Demo action |
| --- | --- |
| **Overview** | Inspect the event distribution and open the evidence IDs behind a detection candidate. |
| **Evidence Vault** | Import `demo/openssh-correlation-demo.log`, a synthetic demo fixture. Search for `login.failed`, filter by event family, and browse 50 records per page. |
| **Detection Center** | Review the SSH correlation candidate. The rule requires at least three failures from the same source IP within 15 minutes before a success. GitHub and OAuth control changes are shown as separate review signals. |
| **Investigation Assistant** | Select **Draft incident brief** and ask about `login.failed`. Expand the workflow trace, or select **Generate investigation timeline** and open a linked Evidence Vault record. |
| **Analyst Cases** | Create a case, choose a severity, add a note, and review the audit timeline. Select **Print / Save as PDF** and choose the browser’s PDF destination. |
| **Model Intelligence** | Select a CICIDS2017 CSV, score an individual flow, or score the full file. The batch attack rate is the fraction of scored flows classified as attack. |

## Generative AI workflow

LangGraph runs five stages: **Triage → Evidence collection → Correlation → Reference retrieval → Response synthesis**. The assistant retrieves up to 25 stored event summaries and finds relevant excerpts from a curated knowledge base. Gemini uses that context to write an answer, brief, or checklist. Event IDs point to stored evidence, while citations point to background guidance.

The app tries configured Gemini alternatives when a model fails. If the provider stays unavailable, it labels the rule-based response `local-rag-fallback`. The timeline is drawn from stored events and works independently of Gemini. See [RAG details](docs/RAG.md).

## Dataset, training, and inference

The CICIDS2017 training workflow uses the labeled `MachineLearningCVE` CSVs. The recorded run sampled **400,000 rows from eight files** and retained **78 numeric features** after removing the label. The training script fits median imputation on the training partition, uses a stratified 80/20 split, and saves both the fitted models and their input schema.

- **Random Forest** classifies individual flows as benign or attack.
- **Isolation Forest** flags unusual flows independently of the classifier.

To train artifacts for a local demo, run these commands from the repository root in PowerShell:

```powershell
python -m pip install -e ./backend
$env:PYTHONPATH = "backend"
python scripts/train_cicids2017.py "C:\path\to\MachineLearningCVE" --rows-per-file 50000 --output models
docker compose restart api
```

The API mounts `models/` read-only. Use artifacts you trained or obtained from a trusted source. Flow models accept the CICIDS2017 feature schema. OpenSSH and GitHub logs go through evidence ingestion and rule-based review. See [measured results and evaluation limits](docs/ML_EVALUATION.md).

## Validate

- From the repository root, run `./scripts/check-demo.ps1` with the demo stack running.
- In `backend/`, install with `python -m pip install -e ".[dev]"` and run `python -m pytest`.
- In `frontend/`, run `npm ci` and `npm run build`.
- With the demo running and evidence loaded, run `npx playwright install chromium --only-shell` and `npx playwright test e2e/demo.spec.ts` from `frontend/`.

## Status

See the [development progress log](docs/DEVELOPMENT_PROGRESS.md) for implementation status. Production configuration disables demo access and public registration. A production rollout still needs a hosting environment with TLS, backups, and monitoring.

