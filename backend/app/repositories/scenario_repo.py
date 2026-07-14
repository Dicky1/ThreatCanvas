from sqlalchemy.orm import Session
from app.models.scenario import ScenarioRecord as Scenario
from app.schemas.cir import CIRSpecification

class ScenarioRepository:
    def __init__(self, db: Session):
        self.db = db

    def save_scenario(self, original_input: str, cir_graph_data: dict) -> Scenario:
        db_scenario = Scenario(
            original_input=original_input,
            cir_graph_data=cir_graph_data
        )
        self.db.add(db_scenario)
        self.db.commit()
        self.db.refresh(db_scenario)
        return db_scenario

    def get_all(self) -> list[Scenario]:  # <--- METODE INI HARUS ADA
        return self.db.query(Scenario).order_by(Scenario.created_at.desc()).all()

    def get_by_id(self, scenario_id: str) -> Scenario | None:
        return self.db.query(Scenario).filter(Scenario.id == scenario_id).first()

    def get_cir(self, scenario_id: str) -> CIRSpecification | None:
        scenario = self.db.query(Scenario).filter(Scenario.id == scenario_id).first()
        if scenario and scenario.cir_graph_data:
            return CIRSpecification(**scenario.cir_graph_data)
        return None

    def delete(self, scenario_id: str) -> bool:
        scenario = self.db.query(Scenario).filter(Scenario.id == scenario_id).first()
        if scenario:
            self.db.delete(scenario)
            self.db.commit()
            return True
        return False