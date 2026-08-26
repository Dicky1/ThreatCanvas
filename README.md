# ThreatCanvas

ThreatCanvas is an AI-assisted cyber engineering workspace for turning natural-language attack narratives and CTI packages into structured CIR graphs, ATT&CK-aware analysis, detection artifacts, collective-defense insights, and measurable defense simulations.

The project is built around a clear separation of concerns:

- **Threat Modeling / Attack Graph** models the ordered attack path for the active scenario.
- **Knowledge Graph** explores CIR entities, provenance, evidence, and typed relationships.
- **Threat Intelligence** imports STIX and normalizes TAXII/MISP/OpenCTI-style payloads.
- **Collective Defense** correlates sanitized packages into shared techniques, paths, coverage gaps, and a collective threat graph.
- **Simulation** measures how blocked techniques disrupt attack paths using APDS, RW-APDS, D3FEND-aligned recommendations, and optional budget optimization.

## Current Capabilities

- Natural-language scenario parsing into CIR v2.
- CIR validation, normalization, evidence enrichment, provenance, confidence, and ATT&CK resolution.
- Attack graph visualization with search, relationship filtering, critical path, high-risk nodes, blast radius, and graph metrics.
- Critical path explainer with missing detection details, asset-aware risk signals, trust-zone grouping, and most-likely path probability.
- Attack graph time machine that replays ordered scenario steps.
- Knowledge Graph explorer for entities, typed relationships, provenance, related attack steps, and STIX metadata.
- MITRE ATT&CK coverage analysis.
- Threat reasoning and assessment.
- Sigma, KQL, and SPL detection artifact generation.
- Detection validation with syntax, schema, telemetry, ATT&CK mapping, malicious-event testing, benign-event testing, precision, recall, and F1.
- Attack simulation with APDS/RW-APDS, before/after metrics, removed nodes, remaining nodes, and optimized controls.
- Bundled D3FEND-aligned seed mappings for defense explanations.
- Budget-aware defense optimization using supplied controls.
- STIX 2.1 import/export.
- CTI connector normalization for STIX/TAXII/MISP/OpenCTI-style JSON payloads.
- Multi-model CIR consensus analysis for agreed/disputed ATT&CK techniques.
- Collective defense correlation with local-vs-collective detection union coverage.
- Research telemetry for parse, detection-validation, and simulation runs plus benchmark summary visualization.
- Benchmark fixtures, sample CIR outputs, and a deterministic benchmark evaluator.
- JWT authentication, scenario history, prompt library UI, and persisted notification history with offline-safe local fallback.

## Architecture

```text
Threat Narrative / CTI / STIX
            |
            v
LLM Parser + CTI Normalization
            |
            v
CIR v2 Graph + Entities + Evidence + Provenance
            |
            +--> ATT&CK Validation / Coverage
            +--> Knowledge Graph Explorer
            +--> Detection Compilation + Validation
            +--> Graph Analysis + Critical Path Explainer
            +--> Threat Reasoning
            +--> Simulation + APDS/RW-APDS + D3FEND + Budget Optimization
            +--> Collective Defense Graph
```

```text
frontend/ React 19 + TypeScript + Vite + React Router 7 + Zustand
    |
    | REST API
    v
backend/ FastAPI + Pydantic v2 + SQLAlchemy + SQLite/PostgreSQL
```

## Project Structure

```text
ThreatCanvas/
├── backend/
│   ├── app/
│   │   ├── api/endpoints/       # auth, parser, coverage, graph, reasoning,
│   │   │                         # simulation, STIX, CTI, consensus, timeline,
│   │   │                         # research, benchmark, notifications
│   │   ├── core/                # config, database, security
│   │   ├── data/                # detection fixtures and D3FEND seed mappings
│   │   ├── models/              # scenarios, experiments, notifications, users
│   │   ├── repositories/        # persistence helpers
│   │   ├── schemas/             # Pydantic API/CIR schemas
│   │   └── services/            # parsing, validation, graph, CTI, STIX,
│   │                             # D3FEND, simulation, benchmark support
│   ├── tests/
│   ├── requirements.txt
│   └── README.md
├── benchmark/
│   ├── narratives/
│   ├── ground_truth/
│   ├── results/
│   └── evaluation/
├── docs/images/
└── frontend/
    ├── src/
    │   ├── api/
    │   ├── components/
    │   ├── pages/
    │   ├── store/
    │   ├── types/
    │   └── utils/
    └── package.json
```

## Backend Setup

Run from `backend/`:

```bash
python -m venv .venv
```

Activate the environment:

```bash
# Windows PowerShell
.venv\Scripts\Activate.ps1

# macOS/Linux
source .venv/bin/activate
```

Install dependencies and create local configuration:

```bash
python -m pip install -r requirements.txt
cp .env.example .env
```

On PowerShell:

```powershell
Copy-Item .env.example .env
```

Set a real `SECRET_KEY` in `.env`:

```bash
python -c "import secrets; print(secrets.token_urlsafe(32))"
```

Start the API:

```bash
uvicorn app.main:app --reload --port 8000
```

The backend runs at `http://localhost:8000`; OpenAPI docs are available at `http://localhost:8000/docs`.

## Frontend Setup

Run from `frontend/`:

```bash
npm install
npm run dev
```

The frontend normally runs at `http://localhost:5173`. If that port is busy, Vite will choose the next available port.

## First User

```bash
curl -X POST http://localhost:8000/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{"username":"analyst","email":"analyst@threatcanvas.local","full_name":"Security Analyst","password":"a-strong-password"}'
```

Then sign in through the frontend login page.

## Environment Variables

| Variable | Purpose | Default |
|---|---|---|
| `PROJECT_NAME` | Application name | `ThreatCanvas AI` |
| `ENVIRONMENT` | Runtime environment label | `development` |
| `OPENAI_API_KEY` | LLM provider API key | empty |
| `OPENAI_API_BASE` | OpenAI-compatible API base URL | `YOUR API BASE URL` |
| `DATABASE_URL` | SQLAlchemy database URL | `sqlite:///./threatcanvas.db` |
| `REDIS_URL` | Reserved for Redis-backed extensions | `redis://localhost:6379/0` |
| `SECRET_KEY` | JWT signing secret | must be replaced |
| `ALGORITHM` | JWT signing algorithm | `HS256` |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | Access token lifetime | `1440` |
| `ATTACK_STIX_PATH` | Optional local ATT&CK STIX bundle path | unset |
| `D3FEND_MAPPING_PATH` | Optional custom D3FEND mapping JSON path | bundled seed mapping |
| `RW_APDS_WEIGHTS_JSON` | Optional RW-APDS weight override JSON | built-in weights |

## API Reference

Most endpoints are under `/api/v1`. STIX endpoints currently use `/api/stix`. Use `/docs` from the running backend as the source of truth for request/response schemas.

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/api/v1/auth/register` | Register a user |
| `POST` | `/api/v1/auth/login` | Login and receive a JWT |
| `POST` | `/api/v1/parse` | Parse a narrative into CIR v2 |
| `GET` | `/api/v1/scenarios` | List saved scenarios |
| `GET` | `/api/v1/scenarios/{scenario_id}` | Read one saved scenario |
| `DELETE` | `/api/v1/scenarios/{scenario_id}` | Delete a saved scenario |
| `GET` | `/api/v1/scenarios/{scenario_id}/evidence` | Read scenario evidence |
| `GET` | `/api/v1/coverage/{scenario_id}` | ATT&CK coverage report |
| `GET` | `/api/v1/graph-analysis/{scenario_id}` | Graph metrics, critical path explanation, probability, asset risk, and trust signals |
| `GET` | `/api/v1/reasoning/{scenario_id}` | Threat reasoning and recommendations |
| `GET` | `/api/v1/compile/{type}/{scenario_id}` | Compile `sigma`, `kql`, or `spl` |
| `POST` | `/api/v1/validate/{type}/{scenario_id}` | Validate generated detection artifacts |
| `POST` | `/api/v1/{scenario_id}` | Run APDS/RW-APDS simulation and defense optimization |
| `GET` | `/api/v1/research/metrics/{scenario_id}` | Read research telemetry |
| `GET` | `/api/v1/notifications` | Read persisted notification history |
| `POST` | `/api/v1/notifications` | Persist a notification event |
| `PATCH` | `/api/v1/notifications/{id}/read` | Mark a notification as read |
| `DELETE` | `/api/v1/notifications` | Clear notification history |
| `GET` | `/api/v1/benchmark/report/summary` | Read bundled benchmark report summary |
| `GET` | `/api/v1/benchmark/{scenario_id}` | Read active-scenario benchmark summary |
| `POST` | `/api/v1/collective/analyze` | Analyze sanitized collective-defense packages |
| `POST` | `/api/v1/cti/fetch` | Normalize STIX/TAXII/MISP/OpenCTI-style JSON payloads |
| `POST` | `/api/v1/consensus/analyze` | Analyze multi-model CIR consensus |
| `GET` | `/api/v1/timeline/{scenario_id}` | Build attack timeline replay data |
| `POST` | `/api/stix/import` | Import STIX 2.1 bundle |
| `GET` | `/api/stix/export/{scenario_id}` | Export scenario as STIX |
| `GET` | `/health` | Health check |

## Benchmark

The benchmark folder includes sample narratives, ground truth, sample CIR results, and a deterministic evaluator.

Run from the repository root:

```bash
python -m benchmark.evaluation.report --cir-dir benchmark/results --output benchmark/results/report.json
```

The evaluator reports:

- CIR schema validity
- ATT&CK precision, recall, and F1
- tactic recall
- graph ordering accuracy

The sample results are intentionally small demonstration fixtures. Replace or extend `benchmark/results/*.json` with parser outputs to produce real experiment numbers.

## Tests

Backend:

```powershell
cd backend
$env:PYTHONPATH='.'
pytest
```

Frontend:

```powershell
cd frontend
npm run build
npm run lint
npm run test
```

Benchmark:

```powershell
python -m benchmark.evaluation.report --cir-dir benchmark/results
```

Current local verification status:

- Backend tests: `33 passed`
- Frontend build: passing
- Frontend lint: passing
- Benchmark sample report: `3` scenarios

## Current Limitations

- TAXII, MISP, and OpenCTI support is a generic JSON connector contract, not a full vendor-specific production integration with pagination, auth flows, and long-running sync.
- D3FEND uses a bundled seed mapping unless `D3FEND_MAPPING_PATH` points to a richer mapping file.
- Benchmark sample results are demonstration fixtures; paper-grade numbers should be generated from fresh parser runs and larger ground truth.
- Prompt Library is currently frontend-managed data, not a backend CRUD resource.
- Notification history is persisted by the backend; the frontend keeps an offline-safe local fallback when the API is unavailable.
- Redis/Celery dependencies are present for future async extensions, but the current request path is synchronous.

## License

MIT
