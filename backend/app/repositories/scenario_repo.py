from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from app.models.scenario import ScenarioRecord as Scenario
from app.models.workspace import WorkspaceMember
from app.schemas.cir import CIRSpecification
from app.services.evidence_provenance import EvidenceProvenanceEngine

EDIT_ROLES = ("owner", "editor")


def scenario_cir(scenario: Scenario) -> CIRSpecification | None:
    """CIR stored on a scenario row (older rows may wrap it in {"cir": ...})."""
    data = scenario.cir_graph_data
    if not data:
        return None
    if isinstance(data, dict) and "attack_graph" not in data and isinstance(data.get("cir"), dict):
        data = data["cir"]
    return CIRSpecification(**data)


class ScenarioRepository:
    """Every read/write is scoped to the requesting user: their own scenarios
    plus scenarios shared into workspaces they belong to. There is no
    unscoped lookup, so a forgotten filter cannot leak another user's data."""

    def __init__(self, db: Session):
        self.db = db

    def save_scenario(self, original_input: str, cir_graph_data: dict, owner_id: str, workspace_id: str | None = None) -> Scenario:
        if not owner_id:
            raise ValueError("owner_id is required")
        if workspace_id and self.workspace_role(workspace_id, owner_id) not in EDIT_ROLES:
            raise PermissionError("Not allowed to add scenarios to this workspace")
        if "attack_graph" in cir_graph_data:
            cir = CIRSpecification.model_validate(cir_graph_data)
            cir_graph_data = EvidenceProvenanceEngine.enrich(cir).model_dump(mode="json")

        db_scenario = Scenario(
            original_input=original_input,
            cir_graph_data=cir_graph_data,
            owner_id=owner_id,
            workspace_id=workspace_id,
        )
        self.db.add(db_scenario)
        self.db.commit()
        self.db.refresh(db_scenario)
        return db_scenario

    def workspace_role(self, workspace_id: str, user_id: str) -> str | None:
        member = (
            self.db.query(WorkspaceMember)
            .filter(WorkspaceMember.workspace_id == workspace_id, WorkspaceMember.user_id == user_id)
            .first()
        )
        return member.role if member else None

    def _accessible(self, user_id: str):
        my_workspaces = select(WorkspaceMember.workspace_id).where(WorkspaceMember.user_id == user_id)
        return self.db.query(Scenario).filter(
            or_(Scenario.owner_id == user_id, Scenario.workspace_id.in_(my_workspaces))
        )

    def list_for_owner(self, owner_id: str, workspace: str | None = None) -> list[Scenario]:
        """``workspace``: None = everything accessible, "personal" = own unshared, else a workspace id."""
        query = self._accessible(owner_id)
        if workspace == "personal":
            query = query.filter(Scenario.owner_id == owner_id, Scenario.workspace_id.is_(None))
        elif workspace:
            query = query.filter(Scenario.workspace_id == workspace)
        return query.order_by(Scenario.created_at.desc()).all()

    def get_scenario(self, scenario_id: str, owner_id: str) -> Scenario | None:
        if not owner_id:
            return None
        return self._accessible(owner_id).filter(Scenario.id == scenario_id).first()

    def get_cir(self, scenario_id: str, owner_id: str) -> CIRSpecification | None:
        scenario = self.get_scenario(scenario_id, owner_id)
        return scenario_cir(scenario) if scenario else None

    def can_edit(self, scenario: Scenario, user_id: str) -> bool:
        if scenario.owner_id == user_id:
            return True
        return bool(scenario.workspace_id) and self.workspace_role(scenario.workspace_id, user_id) in EDIT_ROLES

    def delete(self, scenario_id: str, owner_id: str) -> bool:
        """Owner or workspace owner/editor; viewers cannot delete. Returns
        False when the scenario is not visible; raises PermissionError when
        it is visible but not editable."""
        scenario = self.get_scenario(scenario_id, owner_id)
        if scenario is None:
            return False
        if not self.can_edit(scenario, owner_id):
            raise PermissionError("Viewers cannot delete scenarios")
        self.db.delete(scenario)
        self.db.commit()
        return True

    def set_workspace(self, scenario: Scenario, user_id: str, workspace_id: str | None) -> Scenario:
        """Only the scenario's creator shares/unshares it, into a workspace
        where they are owner or editor."""
        if scenario.owner_id != user_id:
            raise PermissionError("Only the scenario's creator can change its workspace")
        if workspace_id and self.workspace_role(workspace_id, user_id) not in EDIT_ROLES:
            raise PermissionError("You need owner or editor rights in the target workspace")
        scenario.workspace_id = workspace_id
        self.db.commit()
        self.db.refresh(scenario)
        return scenario
