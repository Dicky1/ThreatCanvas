"""Reverse direction: SIEM alerts and CTI reports (PDF / URL / text) -> CIR."""

from functools import partial
from time import perf_counter

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile
from sqlalchemy.orm import Session
from starlette.concurrency import run_in_threadpool

from app.api.deps import get_current_user
from app.api.endpoints.parser import (
    attack_knowledge,
    record_metric,
    run_llm_pipeline,
    save_result,
)
from app.core.database import get_db
from app.models.user import UserRecord
from app.services import llm_parser
from app.services.alert_ingest import (
    ALERT_LLM_INSTRUCTIONS,
    CTI_LLM_INSTRUCTIONS,
    AlertIngestError,
    alerts_narrative,
    alerts_to_cir,
    load_alert_documents,
)
from app.services.cir_pipeline import finalize
from app.services.cti_documents import (
    MAX_DOCUMENT_BYTES,
    DocumentError,
    extract_text,
    truncate_for_llm,
)
from app.services.safe_fetch import FetchBlockedError, fetch

router = APIRouter(prefix="/ingest", tags=["Ingest"])

MAX_ALERT_FILE_BYTES = 20 * 1024 * 1024
MAX_PASTED_TEXT = 200_000


def _generator(instructions: str):
    # Resolved at call time so tests can substitute the LLM.
    return partial(llm_parser.parse_narrative_to_cir, instructions=instructions)


async def _read_limited(upload: UploadFile, limit: int) -> bytes:
    data = await upload.read(limit + 1)
    if len(data) > limit:
        raise HTTPException(status_code=413, detail=f"File exceeds {limit // (1024 * 1024)} MB")
    return data


@router.post("/alerts")
async def ingest_alerts(
    file: UploadFile = File(...),
    use_llm: bool = Form(default=False),
    db: Session = Depends(get_db),
    current_user: UserRecord = Depends(get_current_user),
):
    """Alerts with ATT&CK techniques are converted deterministically; with
    ``use_llm`` alerts without techniques are reconstructed by the LLM."""
    started = perf_counter()
    data = await _read_limited(file, MAX_ALERT_FILE_BYTES)
    try:
        documents = await run_in_threadpool(load_alert_documents, data)
    except AlertIngestError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error

    conversion = alerts_to_cir(documents, attack_knowledge)
    stats = {
        "alerts": len(conversion.alerts),
        "alerts_with_techniques": conversion.used_alerts,
        "skipped_techniques": conversion.skipped_techniques,
    }
    filename = (file.filename or "alerts.json").replace("\\", "/").rsplit("/", 1)[-1][:200]
    original_input = f"[SIEM alerts] {filename}\n\n" + alerts_narrative(conversion.alerts, limit=60)

    if conversion.cir is not None:
        cir, validation = finalize(conversion.cir, attack_knowledge)
        if not validation["valid"]:
            record_metric(db, started, "ingest_alerts", "validation_failed", details={"errors": validation["errors"][:20]})
            raise HTTPException(status_code=400, detail={"message": "Validation Failed", "validation": validation, "repair_attempts": []})
        response = save_result(db, started, "ingest_alerts", original_input, cir, validation, current_user.id,
                               extra_details={"method": "deterministic", **stats})
        return {**response, "method": "deterministic", "stats": stats}

    if not use_llm:
        raise HTTPException(
            status_code=400,
            detail="None of the alerts carries a known ATT&CK technique id. Enable 'Reconstruct with AI' to let the LLM infer the attack chain.",
        )
    digest = alerts_narrative(conversion.alerts)
    result = await run_llm_pipeline(digest, _generator(ALERT_LLM_INSTRUCTIONS), db, started, "ingest_alerts")
    response = save_result(db, started, "ingest_alerts", original_input, result.cir, result.validation, current_user.id,
                           result.attempts, extra_details={"method": "llm", **stats})
    return {**response, "method": "llm", "stats": stats}


@router.post("/cti")
async def ingest_cti(
    file: UploadFile | None = File(default=None),
    url: str | None = Form(default=None, max_length=2000),
    text: str | None = Form(default=None, max_length=MAX_PASTED_TEXT),
    db: Session = Depends(get_db),
    current_user: UserRecord = Depends(get_current_user),
):
    """Exactly one of: a report file (PDF/HTML/text), a URL, or pasted text."""
    has_file = file is not None and bool(file.filename)
    provided = sum([has_file, bool(url and url.strip()), bool(text and text.strip())])
    if provided != 1:
        raise HTTPException(status_code=400, detail="Provide exactly one of: file, url or text")

    started = perf_counter()
    try:
        if has_file:
            data = await _read_limited(file, MAX_DOCUMENT_BYTES)
            source = (file.filename or "report").replace("\\", "/").rsplit("/", 1)[-1][:200]
            title, body = await run_in_threadpool(extract_text, data, source, file.content_type or "")
        elif url:
            try:
                fetched = await run_in_threadpool(
                    partial(fetch, url.strip(), max_bytes=MAX_DOCUMENT_BYTES, accept="text/html,application/pdf,text/plain;q=0.9")
                )
            except FetchBlockedError as error:
                raise HTTPException(status_code=400, detail=str(error)) from error
            source = fetched.url
            title, body = await run_in_threadpool(extract_text, fetched.body, fetched.url.rsplit("/", 1)[-1], fetched.content_type)
        else:
            source = "pasted text"
            title, body = extract_text(text.encode("utf-8"), "pasted.txt", "text/plain")
    except DocumentError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error

    llm_text, truncated = truncate_for_llm(body)
    result = await run_llm_pipeline(llm_text, _generator(CTI_LLM_INSTRUCTIONS), db, started, "ingest_cti")
    header = f"[CTI report] {title or source}\nSource: {source}"
    original_input = f"{header}\n\n{body[:4000]}"
    response = save_result(db, started, "ingest_cti", original_input, result.cir, result.validation, current_user.id,
                           result.attempts, extra_details={"source_chars": len(body), "truncated": truncated})
    return {**response, "source": {"title": title, "location": source, "characters": len(body), "truncated": truncated}}
