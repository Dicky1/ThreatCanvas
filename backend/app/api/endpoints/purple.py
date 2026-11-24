"""Purple team loop: export Atomic Red Team / Caldera plans for a scenario,
then import execution results and see which techniques were detected."""

import logging
from dataclasses import asdict
from typing import Literal

from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, UploadFile
from fastapi.responses import Response
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.api.deps import get_current_user, get_owned_cir
from app.core.database import get_db
from app.models.detection import DetectionDataset
from app.models.purple import PurpleRun
from app.models.user import UserRecord
from app.repositories.scenario_repo import ScenarioRepository
from app.schemas.cir import CIRSpecification
from app.services.detection_lab import LabDataset, evaluate
from app.services.purple_team import (
    MAX_EXECUTION_LOG_BYTES,
    PLATFORMS,
    PurpleTeamError,
    build_plan,
    parse_execution_log,
    render_caldera_bundle,
    render_invoke_atomic,
    technique_results,
)
from app.services.sigma_compiler import SigmaCompiler

router = APIRouter(prefix="/purple", tags=["Purple Team"])
logger = logging.getLogger(__name__)

Platform = Literal["windows", "linux", "macos"]


class ExportRequest(BaseModel):
    format: Literal["invoke-atomic", "caldera"]
    platform: Platform = "windows"
    test_guids: list[str] | None = Field(default=None, max_length=200)


@router.get("/plan/{scenario_id}")
def get_plan(
    platform: Platform = Query(default="windows"),
    cir: CIRSpecification = Depends(get_owned_cir),
):
    plan = build_plan(cir, platform)
    return {
        "platform": platform,
        "platforms": list(PLATFORMS),
        "steps": [asdict(step) for step in plan],
        "coverage": {
            "steps": len(plan),
            "steps_with_tests": sum(1 for step in plan if step.tests),
        },
    }


@router.post("/export/{scenario_id}")
def export_plan(request: ExportRequest, cir: CIRSpecification = Depends(get_owned_cir)):
    plan = build_plan(cir, request.platform)
    try:
        if request.format == "invoke-atomic":
            content = render_invoke_atomic(cir, plan, request.test_guids)
            return Response(
                content,
                media_type="text/plain; charset=utf-8",
                headers={"Content-Disposition": 'attachment; filename="threatcanvas-atomic-plan.ps1"'},
            )
        bundle = render_caldera_bundle(cir, plan, request.test_guids, request.platform)
    except PurpleTeamError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error
    return Response(
        bundle,
        media_type="application/zip",
        headers={"Content-Disposition": 'attachment; filename="threatcanvas-caldera-bundle.zip"'},
    )


def _run_payload(run: PurpleRun) -> dict:
    return {
        "id": run.id,
        "scenario_id": run.scenario_id,
        "dataset_id": run.dataset_id,
        "dataset_name": run.dataset_name,
        "platform": run.platform,
        "summary": run.summary,
        "techniques": run.techniques,
        "executions": run.executions,
        "created_at": run.created_at,
    }


@router.post("/runs", status_code=201)
def create_run(
    scenario_id: str = Form(...),
    dataset_id: str = Form(...),
    platform: Platform = Form(default="windows"),
    execution_log: UploadFile | None = File(default=None),
    db: Session = Depends(get_db),
    current_user: UserRecord = Depends(get_current_user),
):
    cir = ScenarioRepository(db).get_cir(scenario_id, current_user.id)
    if cir is None:
        raise HTTPException(status_code=404, detail="Scenario not found")
    dataset = (
        db.query(DetectionDataset)
        .filter(DetectionDataset.id == dataset_id, DetectionDataset.owner_id == current_user.id)
        .first()
    )
    if dataset is None:
        raise HTTPException(status_code=404, detail="Dataset not found")

    executions = None
    if execution_log is not None and execution_log.filename:
        # Sync endpoint (threadpool): evaluating a 50k-event dataset must not block the event loop.
        data = execution_log.file.read(MAX_EXECUTION_LOG_BYTES + 1)
        try:
            executions = parse_execution_log(execution_log.filename, data)
        except PurpleTeamError as error:
            raise HTTPException(status_code=400, detail=str(error)) from error

    sigma_yaml = SigmaCompiler(cir).compile()
    try:
        evaluation = evaluate(
            sigma_yaml,
            [LabDataset(dataset.id, dataset.name, dataset.label, dataset.technique_ids or [], dataset.events or [])],
        )
    except Exception as error:
        logger.error("Purple run evaluation failed: %s", error, exc_info=True)
        raise HTTPException(status_code=500, detail="Evaluasi gagal karena kesalahan internal.") from error
    results = technique_results(cir, evaluation, executions)
    results["summary"]["truncated"] = evaluation["truncated"]

    run = PurpleRun(
        owner_id=current_user.id,
        scenario_id=scenario_id,
        dataset_id=dataset.id,
        dataset_name=dataset.name,
        platform=platform,
        summary=results["summary"],
        techniques=results["techniques"],
        executions=[asdict(e) for e in executions] if executions is not None else None,
    )
    db.add(run)
    db.commit()
    db.refresh(run)
    return _run_payload(run)


@router.get("/runs")
def list_runs(
    scenario_id: str | None = None,
    db: Session = Depends(get_db),
    current_user: UserRecord = Depends(get_current_user),
):
    query = db.query(PurpleRun).filter(PurpleRun.owner_id == current_user.id)
    if scenario_id:
        query = query.filter(PurpleRun.scenario_id == scenario_id)
    return [_run_payload(run) for run in query.order_by(PurpleRun.created_at.desc()).limit(100)]


def _owned_run(run_id: str, db: Session, user: UserRecord) -> PurpleRun:
    run = db.query(PurpleRun).filter(PurpleRun.id == run_id, PurpleRun.owner_id == user.id).first()
    if run is None:
        raise HTTPException(status_code=404, detail="Run not found")
    return run


@router.get("/runs/{run_id}")
def get_run(run_id: str, db: Session = Depends(get_db), current_user: UserRecord = Depends(get_current_user)):
    return _run_payload(_owned_run(run_id, db, current_user))


@router.delete("/runs/{run_id}")
def delete_run(run_id: str, db: Session = Depends(get_db), current_user: UserRecord = Depends(get_current_user)):
    db.delete(_owned_run(run_id, db, current_user))
    db.commit()
    return {"message": "Run deleted"}
