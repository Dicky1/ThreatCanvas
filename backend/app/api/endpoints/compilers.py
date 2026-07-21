from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.repositories.scenario_repo import ScenarioRepository
from app.schemas.cir import CIRSpecification
from app.services.sigma_compiler import SigmaCompiler
from app.services.kql_compiler import KQLCompiler  # Pastikan file ini sudah ada
from app.services.spl_compiler import SPLCompiler  # Pastikan file ini sudah ada
from pydantic import BaseModel

router = APIRouter()


class CompilerResponse(BaseModel):
    artifact_type: str
    content: str


@router.get("/compile/{type}/{scenario_id}", response_model=CompilerResponse)
def compile_artifact(type: str, scenario_id: str, db: Session = Depends(get_db)):
    repo = ScenarioRepository(db)
    record = repo.get_by_id(scenario_id)

    if not record:
        raise HTTPException(status_code=404, detail="Scenario tidak ditemukan")

    try:
        # Konversi data database ke model CIRSpecification
        cir_data = CIRSpecification(**record.cir_graph_data)

        # Routing compiler berdasarkan tipe yang diminta
        if type == "sigma":
            content = SigmaCompiler(cir_data).compile()
        elif type == "kql":
            content = KQLCompiler(cir_data).compile()
        elif type == "spl":
            content = SPLCompiler(cir_data).compile()
        else:
            raise HTTPException(
                status_code=400,
                detail="Tipe artifact tidak didukung. Gunakan: sigma, kql, atau spl.",
            )

        return CompilerResponse(artifact_type=type, content=content)

    except Exception as e:
        # Log error untuk debugging di terminal
        print(f"Error compiling {type}: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Gagal mengompilasi: {str(e)}")
