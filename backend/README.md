# ThreatCanvas AI Backend

FastAPI backend for turning natural-language attack scenarios into Cyber
Intermediate Representation (CIR) graphs, analyzing those graphs, producing
detection artifacts, and simulating defensive controls.

## Requirements

- Python 3.11 or newer
- SQLite for the default local setup; PostgreSQL is supported through `DATABASE_URL`
- Redis when using features that depend on the configured Redis service

## Local setup

Run these commands from `backend/`:

```bash
python -m venv .venv
```

Activate it with `source .venv/bin/activate` on macOS/Linux or
`.venv\Scripts\Activate.ps1` in PowerShell, then run:

```bash
python -m pip install -r requirements.txt
cp .env.example .env
uvicorn app.main:app --reload
```

On PowerShell, use `Copy-Item .env.example .env` instead of `cp` if needed.
The API runs at `http://127.0.0.1:8000`; OpenAPI documentation is at `/docs`
and the health check is at `/health`.

## Configuration

Local configuration is loaded from `.env`. Start from `.env.example` and put
real credentials only in the untracked `.env` file. Never commit API keys or
production signing secrets.

Settings cover the project environment, OpenAI connection, database, Redis,
and the `SECRET_KEY` used to sign authentication tokens.

## API overview

All application endpoints except `/health` are under `/api/v1`:

- authentication: `/auth/register`, `/auth/login`
- scenarios and CIR parsing: `/parse`, `/scenarios`
- detection generation: `/compile/{type}/{scenario_id}`
- analysis: `/coverage/{scenario_id}`, `/graph-analysis/{scenario_id}`,
  `/reasoning/{scenario_id}`
- simulation: `/{scenario_id}` (POST)

Use the generated OpenAPI page for complete request and response schemas.

## Tests and linting

From `backend/`, run:

```bash
pytest
ruff check app tests
```
