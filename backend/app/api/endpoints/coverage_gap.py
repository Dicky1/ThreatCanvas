"""Real gap analysis: the organisation's existing rules + collected data
sources (DeTT&CT style) against a scenario's techniques."""

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session
from starlette.concurrency import run_in_threadpool

from app.api.deps import get_current_user, get_owned_scenario
from app.api.endpoints.export import _attack_major_version
from app.api.endpoints.parser import attack_knowledge
from app.core.database import get_db
from app.models.coverage_gap import DataSourceProfile, InventoryRule
from app.models.scenario import ScenarioRecord
from app.models.user import UserRecord
from app.repositories.scenario_repo import scenario_cir
from app.services.coverage_gap import (
    MAX_RULE_FILE_BYTES,
    InventoryError,
    all_data_components,
    analyze_gaps,
    navigator_layer,
    parse_dettect,
    parse_rule_inventory,
)
from app.services.sigma_compiler import SigmaCompiler

router = APIRouter(prefix="/coverage-gap", tags=["Coverage Gaps"])


class DataSourceUpdate(BaseModel):
    components: list[str] = Field(..., max_length=500)


def _inventory(db: Session, owner_id: str) -> list[InventoryRule]:
    return db.query(InventoryRule).filter(InventoryRule.owner_id == owner_id).all()


@router.get("/rules")
def inventory_summary(db: Session = Depends(get_db), current_user: UserRecord = Depends(get_current_user)):
    rules = _inventory(db, current_user.id)
    techniques: dict[str, int] = {}
    for rule in rules:
        for technique in rule.techniques or []:
            techniques[technique] = techniques.get(technique, 0) + 1
    files: dict[str, int] = {}
    for rule in rules:
        files[rule.source_file or "-"] = files.get(rule.source_file or "-", 0) + 1
    return {
        "rules": len(rules),
        "techniques": len(techniques),
        "top_techniques": sorted(techniques.items(), key=lambda item: -item[1])[:15],
        "files": [{"file": name, "rules": count} for name, count in sorted(files.items())][:200],
    }


@router.post("/rules", status_code=201)
async def import_rules(
    file: UploadFile = File(...),
    replace: bool = False,
    db: Session = Depends(get_db),
    current_user: UserRecord = Depends(get_current_user),
):
    data = await file.read(MAX_RULE_FILE_BYTES + 1)
    if len(data) > MAX_RULE_FILE_BYTES:
        raise HTTPException(status_code=413, detail="File too large")
    filename = (file.filename or "rules.yml").replace("\\", "/").rsplit("/", 1)[-1][:200]
    try:
        result = await run_in_threadpool(parse_rule_inventory, filename, data)
    except InventoryError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error
    if replace:
        db.query(InventoryRule).filter(InventoryRule.owner_id == current_user.id).delete()
    existing = 0 if replace else db.query(InventoryRule).filter(InventoryRule.owner_id == current_user.id).count()
    if existing + len(result.rules) > 10_000:
        raise HTTPException(status_code=400, detail="Inventory limit is 10,000 rules; use replace=true or remove rules")
    db.add_all(
        InventoryRule(
            owner_id=current_user.id,
            title=rule.title,
            rule_id=rule.rule_id,
            techniques=rule.techniques,
            logsource=rule.logsource,
            status=rule.status,
            level=rule.level,
            source=rule.source,
            source_file=rule.source_file,
        )
        for rule in result.rules
    )
    db.commit()
    return {"imported": len(result.rules), "skipped_untagged": result.skipped, "errors": result.errors[:50]}


@router.delete("/rules")
def clear_rules(db: Session = Depends(get_db), current_user: UserRecord = Depends(get_current_user)):
    deleted = db.query(InventoryRule).filter(InventoryRule.owner_id == current_user.id).delete()
    db.commit()
    return {"deleted": deleted}


def _profile(db: Session, owner_id: str) -> DataSourceProfile | None:
    return db.query(DataSourceProfile).filter(DataSourceProfile.owner_id == owner_id).first()


@router.get("/data-sources")
def get_data_sources(db: Session = Depends(get_db), current_user: UserRecord = Depends(get_current_user)):
    profile = _profile(db, current_user.id)
    return {
        "configured": profile is not None,
        "components": profile.components if profile else [],
        "source": profile.source if profile else None,
        "catalog": all_data_components(attack_knowledge),
    }


def _save_profile(db: Session, owner_id: str, components: list[str], source: str) -> DataSourceProfile:
    profile = _profile(db, owner_id) or DataSourceProfile(owner_id=owner_id)
    profile.components = components
    profile.source = source
    db.add(profile)
    db.commit()
    db.refresh(profile)
    return profile


@router.put("/data-sources")
def set_data_sources(request: DataSourceUpdate, db: Session = Depends(get_db), current_user: UserRecord = Depends(get_current_user)):
    known = set(all_data_components(attack_knowledge))
    unknown = sorted({c for c in request.components if c not in known})
    if unknown:
        raise HTTPException(status_code=400, detail=f"Unknown ATT&CK data component(s): {', '.join(unknown[:10])}")
    profile = _save_profile(db, current_user.id, sorted(set(request.components)), "manual")
    return {"components": profile.components, "source": profile.source}


@router.post("/data-sources/dettect")
async def import_dettect(
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    current_user: UserRecord = Depends(get_current_user),
):
    data = await file.read(5 * 1024 * 1024 + 1)
    if len(data) > 5 * 1024 * 1024:
        raise HTTPException(status_code=413, detail="File too large")
    try:
        available, unmatched = parse_dettect(data.decode("utf-8", errors="replace"), set(all_data_components(attack_knowledge)))
    except InventoryError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error
    profile = _save_profile(db, current_user.id, available, "dettect")
    return {"components": profile.components, "source": profile.source, "unmatched": unmatched}


def _analysis(scenario: ScenarioRecord, db: Session, user: UserRecord) -> dict:
    cir = scenario_cir(scenario)
    if cir is None:
        raise HTTPException(status_code=400, detail="CIR data is empty for this scenario")
    inventory = [{"title": r.title, "techniques": r.techniques or []} for r in _inventory(db, user.id)]
    profile = _profile(db, user.id)
    generated = {
        str(node.technique).upper()
        for node in cir.attack_graph.nodes
        if SigmaCompiler(cir).rules_for_node(node)
    }
    return analyze_gaps(cir, attack_knowledge, inventory, profile.components if profile else None, generated)


@router.get("/{scenario_id}")
def gap_analysis(
    scenario: ScenarioRecord = Depends(get_owned_scenario),
    db: Session = Depends(get_db),
    current_user: UserRecord = Depends(get_current_user),
):
    return _analysis(scenario, db, current_user)


@router.get("/{scenario_id}/navigator")
def gap_navigator_layer(
    scenario: ScenarioRecord = Depends(get_owned_scenario),
    db: Session = Depends(get_db),
    current_user: UserRecord = Depends(get_current_user),
):
    return navigator_layer(scenario.id, _analysis(scenario, db, current_user), _attack_major_version())
