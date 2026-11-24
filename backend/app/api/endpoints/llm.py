from fastapi import APIRouter

from app.services.llm_client import default_profile, profiles

router = APIRouter(prefix="/llm", tags=["LLM"])


@router.get("/profiles")
def list_profiles():
    """Configured models (names / modes only: no URLs or keys)."""
    return {"default": default_profile().name, "profiles": [p.public() for p in profiles()]}
