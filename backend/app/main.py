from fastapi import Depends, FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.api.deps import get_current_user
from app.api.endpoints import parser, compilers, coverage
from app.core.database import engine, Base
from app.api.endpoints import graph_analysis
from app.api.endpoints import reasoning
from app.api.endpoints import auth
from app.api.endpoints import simulation  # <-- TAMBAHAN PHASE 7
from app.api.endpoints import stix
from app.api.endpoints import collective
from app.api.endpoints import research
from app.api.endpoints import benchmark
from app.api.endpoints import cti
from app.api.endpoints import consensus
from app.api.endpoints import timeline
from app.api.endpoints import notifications
from app.models import user 
from app.models import experiment
from app.models import notification

Base.metadata.create_all(bind=engine)

app = FastAPI(title="ThreatCanvas AI API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5174", "http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# auth.router (login/register) stays public - every other router requires a
# valid JWT via get_current_user, applied once here rather than per-endpoint.
protected = [Depends(get_current_user)]

app.include_router(parser.router, prefix="/api/v1", tags=["Parser"], dependencies=protected)
app.include_router(compilers.router, prefix="/api/v1", tags=["Compilers"], dependencies=protected)
app.include_router(coverage.router, prefix="/api/v1", tags=["Coverage"], dependencies=protected)
app.include_router(graph_analysis.router, prefix="/api/v1", tags=["Analysis"], dependencies=protected)
app.include_router(reasoning.router, prefix="/api/v1", tags=["Reasoning"], dependencies=protected)
app.include_router(auth.router, prefix="/api/v1", tags=["Auth"])
app.include_router(stix.router, dependencies=protected)
app.include_router(collective.router, dependencies=protected)
app.include_router(research.router, prefix="/api/v1", dependencies=protected)
app.include_router(benchmark.router, prefix="/api/v1", dependencies=protected)
app.include_router(cti.router, prefix="/api/v1", dependencies=protected)
app.include_router(consensus.router, prefix="/api/v1", dependencies=protected)
app.include_router(timeline.router, prefix="/api/v1", dependencies=protected)
app.include_router(notifications.router, prefix="/api/v1", dependencies=protected)
# simulation.router declares POST /{scenario_id} with NO prefix of its own,
# i.e. a bare catch-all under /api/v1/. Starlette matches routes in
# registration order (not by specificity), so this MUST stay registered last
# among the /api/v1 routers - otherwise it silently shadows any other
# single-segment /api/v1/<literal> route registered after it (this is
# exactly what broke POST /api/v1/notifications before this was reordered).
app.include_router(simulation.router, prefix="/api/v1", tags=["Simulation"], dependencies=protected)  # <-- TAMBAHAN PHASE 7

@app.get("/health")
async def health_check():
    return {"status": "ok"}
