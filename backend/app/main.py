from fastapi import FastAPI  # type: ignore[reportMissingImports]
from fastapi.middleware.cors import CORSMiddleware
from app.api.endpoints import parser, compilers, coverage
from app.core.database import engine, Base
from app.api.endpoints import graph_analysis

# 1. TAMBAHKAN IMPORT REASONING DI SINI
from app.api.endpoints import reasoning 

# Create Database Tables
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

@app.get("/health")
async def health_check():
    return {"status": "ok"}