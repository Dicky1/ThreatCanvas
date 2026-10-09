from typing import List, Literal
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session
import json

from app.core.database import get_db
from app.api.deps import get_current_user
from app.repositories.scenario_repo import ScenarioRepository
from app.schemas.user import UserRecord
from app.core.config import settings

# Menggunakan AsyncOpenAI agar non-blocking
from openai import AsyncOpenAI
import logging

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/chat", tags=["Chat"])

client = AsyncOpenAI(api_key=settings.OPENAI_API_KEY, base_url=settings.OPENAI_API_BASE)

class ChatMessage(BaseModel):
    role: Literal["user", "assistant", "system"]
    content: str

class ChatRequest(BaseModel):
    messages: List[ChatMessage]

class ChatResponse(BaseModel):
    reply: str

@router.post("/{scenario_id}", response_model=ChatResponse)
async def chat_with_scenario(
    scenario_id: str,
    payload: ChatRequest,
    db: Session = Depends(get_db),
    current_user: UserRecord = Depends(get_current_user)
):
    """
    Tanya-jawab interaktif dengan AI mengenai skenario tertentu.
    Context skenario akan di-inject otomatis ke sistem prompt.
    """
    repo = ScenarioRepository(db)
    scenario = repo.get_scenario(scenario_id, current_user.id)
    
    if not scenario:
        raise HTTPException(status_code=404, detail="Skenario tidak ditemukan")

    cir_data = scenario.cir_graph_data
    
    # Render context secara compact
    context = json.dumps(cir_data, separators=(',', ':')) if cir_data else "{}"
    
    system_prompt = f"""You are the ThreatCanvas AI Copilot, a highly skilled cybersecurity architect.
The user is currently viewing the following threat scenario graph (in CIR v2 JSON format):
{context}

Answer the user's questions about this scenario concisely and professionally. 
If they ask for defenses, prioritize cost-effective or critical-path mitigations. 
Do not output markdown code blocks unless necessary. Keep it conversational."""

    # Siapkan pesan untuk LLM
    api_messages = [{"role": "system", "content": system_prompt}]
    for msg in payload.messages:
        api_messages.append({"role": msg.role, "content": msg.content})

    try:
        response = await client.chat.completions.create(
            model="gpt-4o",  # Atau biarkan proxy SumoPod menangani model
            messages=api_messages,
            max_tokens=800,
            temperature=0.7
        )
        reply_content = response.choices[0].message.content
        return ChatResponse(reply=reply_content)
    except Exception as e:
        logger.error(f"Error AI Copilot chat: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Gagal menghubungi AI Copilot. Terjadi kesalahan internal.")
