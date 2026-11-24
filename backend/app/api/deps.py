from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.core.security import decode_access_token
from app.repositories.user_repo import UserRepository
from app.models.scenario import ScenarioRecord
from app.models.user import UserRecord
from app.repositories.scenario_repo import ScenarioRepository, scenario_cir
from app.schemas.cir import CIRSpecification

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login")


def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db),
) -> UserRecord:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Token tidak valid atau sudah kedaluwarsa",
        headers={"WWW-Authenticate": "Bearer"},
    )

    user_id = decode_access_token(token)
    if user_id is None:
        raise credentials_exception

    user_repo = UserRepository(db)
    user = user_repo.get_by_id(user_id)
    if user is None or not user.is_active:
        raise credentials_exception

    return user

def get_owned_scenario(
    scenario_id: str,
    current_user: UserRecord = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> ScenarioRecord:
    """Resolve the ``scenario_id`` path parameter to a scenario owned by the
    caller. Another user's scenario returns 404 (not 403) so IDs can't be probed."""
    scenario = ScenarioRepository(db).get_scenario(scenario_id, current_user.id)
    if scenario is None:
        raise HTTPException(status_code=404, detail="Scenario not found")
    return scenario


def get_owned_cir(scenario: ScenarioRecord = Depends(get_owned_scenario)) -> CIRSpecification:
    """CIR of a scenario owned by the caller."""
    cir = scenario_cir(scenario)
    if cir is None:
        raise HTTPException(status_code=400, detail="CIR data is empty for this scenario")
    return cir
