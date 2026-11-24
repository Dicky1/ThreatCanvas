from typing import List, Literal
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
import json

from app.api.deps import get_owned_scenario
from app.models.scenario import ScenarioRecord
from app.core.config import settings

# Menggunakan AsyncOpenAI agar non-blocking
from openai import AsyncOpenAI
import logging

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/chat", tags=["Chat"])

client = AsyncOpenAI(api_key=settings.OPENAI_API_KEY, base_url=settings.OPENAI_API_BASE)

class ChatMessage(BaseModel):
    # "system" is reserved for the server-built prompt; clients cannot inject one.
    role: Literal["user", "assistant"]
    content: str = Field(..., min_length=1, max_length=4000)

class ChatRequest(BaseModel):
    messages: List[ChatMessage] = Field(..., min_length=1, max_length=30)

class ChatResponse(BaseModel):
    reply: str

@router.post("/{scenario_id}", response_model=ChatResponse)
async def chat_with_scenario(
    scenario_id: str,
    payload: ChatRequest,
    scenario: ScenarioRecord = Depends(get_owned_scenario),
):
    """
    Tanya-jawab interaktif dengan AI mengenai skenario tertentu.
    Context skenario akan di-inject otomatis ke sistem prompt.
    """

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
