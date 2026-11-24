"""Detection engineering: pySigma conversions and measuring rules against
uploaded log datasets (OTRF Security-Datasets, Atomic Red Team EVTX, ...)."""

import logging
import re
from typing import Literal

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.api.deps import get_current_user, get_owned_cir
from app.core.database import get_db
from app.models.detection import DetectionDataset
from app.models.user import UserRecord
from app.repositories.scenario_repo import ScenarioRepository
from app.schemas.cir import CIRSpecification
from app.services.detection_lab import LabDataset, evaluate
from app.services.log_datasets import MAX_UPLOAD_BYTES, DatasetError, parse_dataset
from app.services.sigma_compiler import SigmaCompiler
from app.services.sigma_conversion import (
    MAX_SIGMA_CHARS,
    TARGETS,
    SigmaConversionError,
    convert,
)

router = APIRouter(prefix="/detection", tags=["Detection Lab"])
logger = logging.getLogger(__name__)

MAX_DATASETS_PER_USER = 50
MAX_DATASETS_PER_EVALUATION = 20
MAX_EVENTS_PER_EVALUATION = 200_000  # bounds memory: events are loaded and indexed in RAM
TECHNIQUE_RE = re.compile(r"^T\d{4}(\.\d{3})?$")


class ConvertRequest(BaseModel):
    sigma: str = Field(..., min_length=1, max_length=MAX_SIGMA_CHARS)


class EvaluateRequest(BaseModel):
    dataset_ids: list[str] = Field(..., min_length=1, max_length=MAX_DATASETS_PER_EVALUATION)
    sigma: str | None = Field(default=None, max_length=MAX_SIGMA_CHARS)
    scenario_id: str | None = None


def _conversion_response(sigma_yaml: str, target: str) -> dict:
    try:
        result = convert(sigma_yaml, target)
    except SigmaConversionError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error
    return {
        "target": target,
        "language": TARGETS[target].language,
        "rules": [
            {
                "title": rule.title,
                "rule_id": rule.rule_id,
                "techniques": rule.techniques,
                "queries": rule.queries,
                "error": rule.error,
            }
            for rule in result.rules
        ],
        "errors": result.errors,
    }


def _check_target(target: str) -> None:
    if target not in TARGETS:
        raise HTTPException(status_code=400, detail=f"Unsupported target. Use one of: {', '.join(TARGETS)}")


@router.get("/targets")
def list_targets():
    return [
        {"key": t.key, "label": t.label, "language": t.language, "description": t.description}
        for t in TARGETS.values()
    ]


@router.get("/convert/{target}/{scenario_id}")
def convert_scenario(target: str, cir: CIRSpecification = Depends(get_owned_cir)):
    _check_target(target)
    sigma_yaml = SigmaCompiler(cir).compile()
    if "title:" in sigma_yaml:
        response = _conversion_response(sigma_yaml, target)
    else:  # no step had a detectable observable: nothing to convert
        response = {"target": target, "language": TARGETS[target].language, "rules": [], "errors": []}
    response["sigma"] = sigma_yaml
    return response


@router.post("/convert/{target}")
def convert_sigma(target: str, request: ConvertRequest):
    _check_target(target)
    return _conversion_response(request.sigma, target)


def _dataset_summary(dataset: DetectionDataset) -> dict:
    return {
        "id": dataset.id,
        "name": dataset.name,
        "label": dataset.label,
        "technique_ids": dataset.technique_ids or [],
        "source_filename": dataset.source_filename,
        "event_count": dataset.event_count,
        "created_at": dataset.created_at,
    }


@router.get("/datasets")
def list_datasets(db: Session = Depends(get_db), current_user: UserRecord = Depends(get_current_user)):
    rows = (
        db.query(DetectionDataset)
        .filter(DetectionDataset.owner_id == current_user.id)
        .order_by(DetectionDataset.created_at.desc())
        .all()
    )
    return [_dataset_summary(row) for row in rows]


@router.post("/datasets", status_code=201)
def upload_dataset(
    file: UploadFile = File(...),
    name: str = Form(..., min_length=1, max_length=120),
    label: Literal["malicious", "benign"] = Form(...),
    technique_ids: str = Form(default="", max_length=500),
    db: Session = Depends(get_db),
    current_user: UserRecord = Depends(get_current_user),
):
    techniques = sorted({t.strip().upper() for t in technique_ids.split(",") if t.strip()})
    invalid = [t for t in techniques if not TECHNIQUE_RE.match(t)]
    if invalid:
        raise HTTPException(status_code=400, detail=f"Invalid ATT&CK technique id(s): {', '.join(invalid)}")
    count = db.query(DetectionDataset).filter(DetectionDataset.owner_id == current_user.id).count()
    if count >= MAX_DATASETS_PER_USER:
        raise HTTPException(status_code=400, detail=f"Dataset limit reached ({MAX_DATASETS_PER_USER}); delete some first")

    # Sync endpoint (runs in the threadpool): parsing a 50 MB archive must not block the event loop.
    data = file.file.read(MAX_UPLOAD_BYTES + 1)
    if len(data) > MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail=f"File exceeds {MAX_UPLOAD_BYTES // (1024 * 1024)} MB")
    filename = (file.filename or "upload.json").replace("\\", "/").rsplit("/", 1)[-1][:200]
    try:
        events = parse_dataset(filename, data)
    except DatasetError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error

    dataset = DetectionDataset(
        owner_id=current_user.id,
        name=name.strip(),
        label=label,
        technique_ids=techniques,
        source_filename=filename,
        event_count=len(events),
        events=events,
    )
    db.add(dataset)
    db.commit()
    db.refresh(dataset)
    return _dataset_summary(dataset)


@router.delete("/datasets/{dataset_id}")
def delete_dataset(dataset_id: str, db: Session = Depends(get_db), current_user: UserRecord = Depends(get_current_user)):
    dataset = (
        db.query(DetectionDataset)
        .filter(DetectionDataset.id == dataset_id, DetectionDataset.owner_id == current_user.id)
        .first()
    )
    if dataset is None:
        raise HTTPException(status_code=404, detail="Dataset not found")
    db.delete(dataset)
    db.commit()
    return {"message": "Dataset deleted"}


@router.post("/evaluate")
def evaluate_rules(
    request: EvaluateRequest,
    db: Session = Depends(get_db),
    current_user: UserRecord = Depends(get_current_user),
):
    if bool(request.sigma) == bool(request.scenario_id):
        raise HTTPException(status_code=400, detail="Provide exactly one of 'sigma' or 'scenario_id'")
    if request.scenario_id:
        cir = ScenarioRepository(db).get_cir(request.scenario_id, current_user.id)
        if cir is None:
            raise HTTPException(status_code=404, detail="Scenario not found")
        sigma_yaml = SigmaCompiler(cir).compile()
    else:
        sigma_yaml = request.sigma or ""

    ids = list(dict.fromkeys(request.dataset_ids))
    rows = (
        db.query(DetectionDataset)
        .filter(DetectionDataset.owner_id == current_user.id, DetectionDataset.id.in_(ids))
        .all()
    )
    if len(rows) != len(ids):
        raise HTTPException(status_code=404, detail="Dataset not found")
    total_events = sum(row.event_count or 0 for row in rows)
    if total_events > MAX_EVENTS_PER_EVALUATION:
        raise HTTPException(
            status_code=400,
            detail=f"Selected datasets hold {total_events:,} events; evaluate at most {MAX_EVENTS_PER_EVALUATION:,} at once",
        )
    by_id = {row.id: row for row in rows}
    datasets = [
        LabDataset(row.id, row.name, row.label, row.technique_ids or [], row.events or [])
        for row in (by_id[i] for i in ids)
    ]
    try:
        report = evaluate(sigma_yaml, datasets)
    except Exception as error:
        logger.error("Detection evaluation failed: %s", error, exc_info=True)
        raise HTTPException(status_code=500, detail="Evaluasi rule gagal karena kesalahan internal.") from error
    report["sigma"] = sigma_yaml
    return report
