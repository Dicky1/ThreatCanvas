from sqlalchemy.orm import Session

from app.models.scenario import ScenarioRecord as Scenario
from app.schemas.cir import CIRSpecification
from app.services.evidence_provenance import EvidenceProvenanceEngine


def scenario_cir(scenario: Scenario) -> CIRSpecification | None:
    """CIR stored on a scenario row (older rows may wrap it in {"cir": ...})."""
    data = scenario.cir_graph_data
    if not data:
        return None
    if isinstance(data, dict) and "attack_graph" not in data and isinstance(data.get("cir"), dict):
        data = data["cir"]
    return CIRSpecification(**data)


class ScenarioRepository:
    """Every read/write is scoped to an owner: there is deliberately no
    unscoped lookup, so a forgotten filter cannot leak another user's data."""

    def __init__(self, db: Session):
        self.db = db

    def save_scenario(self, original_input: str, cir_graph_data: dict, owner_id: str) -> Scenario:
        if not owner_id:
            raise ValueError("owner_id is required")
        if "attack_graph" in cir_graph_data:
            cir = CIRSpecification.model_validate(cir_graph_data)
            cir_graph_data = EvidenceProvenanceEngine.enrich(cir).model_dump(mode="json")

        db_scenario = Scenario(original_input=original_input, cir_graph_data=cir_graph_data, owner_id=owner_id)
        self.db.add(db_scenario)
        self.db.commit()
        self.db.refresh(db_scenario)
        return db_scenario

    def _owned(self, owner_id: str):
        return self.db.query(Scenario).filter(Scenario.owner_id == owner_id)

    def list_for_owner(self, owner_id: str) -> list[Scenario]:
        return self._owned(owner_id).order_by(Scenario.created_at.desc()).all()

    def get_scenario(self, scenario_id: str, owner_id: str) -> Scenario | None:
        if not owner_id:
            return None
        return self._owned(owner_id).filter(Scenario.id == scenario_id).first()

    def get_cir(self, scenario_id: str, owner_id: str) -> CIRSpecification | None:
        scenario = self.get_scenario(scenario_id, owner_id)
        return scenario_cir(scenario) if scenario else None

    def delete(self, scenario_id: str, owner_id: str) -> bool:
        scenario = self.get_scenario(scenario_id, owner_id)
        if scenario is None:
            return False
        self.db.delete(scenario)
        self.db.commit()
        return True
