import json
import logging
from datetime import UTC, datetime, timedelta
from functools import partial
from pathlib import Path

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session, sessionmaker

from app.api.deps import get_current_user, get_owned_cir
from app.api.endpoints.parser import attack_knowledge
from app.core.database import get_db
from app.models.benchmark_run import BenchmarkRun
from app.models.user import UserRecord
from app.schemas.cir import CIRSpecification
from app.services import llm_parser
from app.services.benchmark_runner import load_cases, run_benchmark
from app.services.coverage_analyzer import CoverageAnalyzer
from app.services.llm_client import UnknownProfileError, get_profile

router = APIRouter(prefix="/benchmark", tags=["Benchmark"])
logger = logging.getLogger(__name__)
STALE_RUN = timedelta(hours=2)


class BenchmarkRunRequest(BaseModel):
    profiles: list[str] = Field(..., min_length=1, max_length=4)
    case_ids: list[str] | None = Field(default=None, max_length=50)


@router.get("/cases")
def list_cases():
    return [
        {"id": c["id"], "title": c["title"], "tags": c["tags"], "narrative": c["narrative"],
         "expected_techniques": c["expected_techniques"]}
        for c in load_cases()
    ]


def _run_payload(run: BenchmarkRun) -> dict:
    return {
        "id": run.id,
        "status": run.status,
        "profiles": run.profiles,
        "case_ids": run.case_ids,
        "report": run.report,
        "error": run.error,
        "created_at": run.created_at,
        "finished_at": run.finished_at,
    }


async def _execute(run_id: str, session_factory, profiles: list[str], case_ids: list[str] | None) -> None:
    db = session_factory()
    try:
        run = db.get(BenchmarkRun, run_id)
        run.status = "running"
        db.commit()

        def progress(report: dict) -> None:
            run.report = json.loads(json.dumps(report, default=str))  # new object so SQLAlchemy persists it
            db.commit()

        def generator_for(name: str):
            # Resolved at call time so tests can substitute the LLM.
            return partial(llm_parser.parse_narrative_to_cir, profile=name)

        report = await run_benchmark(profiles, case_ids, generator_for, attack_knowledge, progress)
        run.report = json.loads(json.dumps(report, default=str))
        run.status = "done"
    except Exception as error:  # noqa: BLE001 - surface failure on the run record
        logger.error("Benchmark run %s failed: %s", run_id, error, exc_info=True)
        run = db.get(BenchmarkRun, run_id)
        if run is not None:
            run.status = "failed"
            run.error = "Benchmark run failed; see server logs."
    finally:
        run = db.get(BenchmarkRun, run_id)
        if run is not None:
            run.finished_at = datetime.now(UTC)
            db.commit()
        db.close()


@router.post("/runs", status_code=202)
def start_run(
    request: BenchmarkRunRequest,
    background: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user: UserRecord = Depends(get_current_user),
):
    """Each profile x case costs 1-3 LLM calls; one active run per user."""
    profiles = list(dict.fromkeys(request.profiles))
    for name in profiles:
        try:
            get_profile(name)
        except UnknownProfileError as error:
            raise HTTPException(status_code=400, detail=str(error)) from error
    known = {c["id"] for c in load_cases()}
    unknown = sorted(set(request.case_ids or []) - known)
    if unknown:
        raise HTTPException(status_code=400, detail=f"Unknown benchmark case(s): {', '.join(unknown)}")
    cutoff = datetime.now(UTC) - STALE_RUN
    active = [
        r for r in db.query(BenchmarkRun).filter(BenchmarkRun.owner_id == current_user.id, BenchmarkRun.status.in_(["queued", "running"]))
        if r.created_at is None or r.created_at.replace(tzinfo=r.created_at.tzinfo or UTC) > cutoff
    ]
    if active:
        raise HTTPException(status_code=409, detail="A benchmark run is already in progress")
    run = BenchmarkRun(owner_id=current_user.id, status="queued", profiles=profiles, case_ids=request.case_ids)
    db.add(run)
    db.commit()
    db.refresh(run)
    session_factory = sessionmaker(autocommit=False, autoflush=False, bind=db.get_bind())
    background.add_task(_execute, run.id, session_factory, profiles, request.case_ids)
    return _run_payload(run)


@router.get("/runs")
def list_runs(db: Session = Depends(get_db), current_user: UserRecord = Depends(get_current_user)):
    runs = db.query(BenchmarkRun).filter(BenchmarkRun.owner_id == current_user.id).order_by(BenchmarkRun.created_at.desc()).limit(50)
    return [{**_run_payload(run), "report": None, "summary": {k: v["summary"] for k, v in ((run.report or {}).get("profiles") or {}).items()}} for run in runs]


@router.get("/runs/{run_id}")
def get_run(run_id: str, db: Session = Depends(get_db), current_user: UserRecord = Depends(get_current_user)):
    run = db.query(BenchmarkRun).filter(BenchmarkRun.id == run_id, BenchmarkRun.owner_id == current_user.id).first()
    if run is None:
        raise HTTPException(status_code=404, detail="Run not found")
    return _run_payload(run)


@router.get("/report/summary")
def benchmark_report():
    report_path = Path(__file__).resolve().parents[4] / "benchmark" / "results" / "report.json"
    if not report_path.exists():
        raise HTTPException(status_code=404, detail="Benchmark report not found")
    return json.loads(report_path.read_text(encoding="utf-8"))


@router.get("/{scenario_id}")
def benchmark_scenario(scenario_id: str, cir: CIRSpecification = Depends(get_owned_cir)):
    coverage = CoverageAnalyzer(cir).analyze()
    nodes = cir.attack_graph.nodes
    edges = cir.attack_graph.edges
    return {
        "scenario_id": scenario_id,
        "node_count": len(nodes),
        "edge_count": len(edges),
        "technique_count": len({node.technique for node in nodes}),
        "tactic_count": len({node.tactic for node in nodes}),
        "coverage_score": coverage.get("overall_score"),
        "covered_techniques": coverage.get("covered_techniques", []),
        "missing_techniques": coverage.get("missing_techniques", []),
    }
