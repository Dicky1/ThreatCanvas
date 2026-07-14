from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.schemas.cir import CIRSpecification
from app.services.llm_parser import parse_narrative_to_cir
from app.repositories.scenario_repo import ScenarioRepository

router = APIRouter()


class ParseRequest(BaseModel):
    scenario: str


class ParseResponse(CIRSpecification):
    id: str


@router.post("/parse", response_model=ParseResponse)
async def parse_scenario(
    request: ParseRequest,
    db: Session = Depends(get_db)
):
    """
    Parse Natural Language -> CIR
    lalu simpan CIR ke database.
    """

    if not request.scenario.strip():
        raise HTTPException(
            status_code=400,
            detail="Scenario cannot be empty"
        )

    try:

        # ===========================
        # Generate CIR menggunakan LLM
        # ===========================
        cir_graph = await parse_narrative_to_cir(
            request.scenario
        )

        # ===========================
        # Simpan ke Database
        # ===========================
        repo = ScenarioRepository(db)

        saved_record = repo.save_scenario(
            original_input=request.scenario,
            cir_data=cir_graph
        )

        # ===========================
        # Response
        # ===========================
        response = cir_graph.model_dump()
        response["id"] = str(saved_record.id)

        return response

    except Exception as e:
        print(f"Error pada parse_scenario: {e}")

        raise HTTPException(
            status_code=500,
            detail=str(e)
        )


@router.get("/scenarios")
def get_all_scenarios(
    db: Session = Depends(get_db)
):
    """
    Mengambil seluruh riwayat scenario.
    Digunakan oleh halaman History.
    """

    repo = ScenarioRepository(db)

    return repo.get_all()


@router.get("/scenarios/{scenario_id}")
def get_scenario(
    scenario_id: str,
    db: Session =Depends(get_db)
):
    """
    Mengambil detail satu scenario.
    """

    repo = ScenarioRepository(db)

    scenario = repo.get_scenario(scenario_id)

    if scenario is None:
        raise HTTPException(
            status_code=404,
            detail="Scenario not found"
        )

    return scenario


@router.delete("/scenarios/{scenario_id}")
def delete_scenario(
    scenario_id: str,
    db: Session = Depends(get_db)
):
    """
    Menghapus scenario dari database.
    """

    repo = ScenarioRepository(db)

    deleted = repo.delete_scenario(scenario_id)

    if not deleted:
        raise HTTPException(
            status_code=404,
            detail="Scenario not found"
        )

    return {
        "message": "Scenario deleted successfully"
    }