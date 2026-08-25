from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
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
from app.models import user 
from app.models import experiment

Base.metadata.create_all(bind=engine)

app = FastAPI(title="ThreatCanvas AI API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5174", "http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(parser.router, prefix="/api/v1", tags=["Parser"])
app.include_router(compilers.router, prefix="/api/v1", tags=["Compilers"])
app.include_router(coverage.router, prefix="/api/v1", tags=["Coverage"])
app.include_router(graph_analysis.router, prefix="/api/v1", tags=["Analysis"])
app.include_router(reasoning.router, prefix="/api/v1", tags=["Reasoning"])
app.include_router(auth.router, prefix="/api/v1", tags=["Auth"])
app.include_router(simulation.router, prefix="/api/v1", tags=["Simulation"])  # <-- TAMBAHAN PHASE 7
app.include_router(stix.router)
app.include_router(collective.router)
app.include_router(research.router, prefix="/api/v1")
app.include_router(benchmark.router, prefix="/api/v1")

@app.get("/health")
async def health_check():
    return {"status": "ok"}
