import json
import uuid
import logging
from openai import AsyncOpenAI
from app.schemas.cir import CIRSpecification
from app.core.config import settings

# Setup logging agar kita tahu apa yang terjadi di balik layar
logger = logging.getLogger(__name__)

client = AsyncOpenAI(
    api_key=settings.OPENAI_API_KEY,
    base_url=settings.OPENAI_API_BASE 
)

async def parse_narrative_to_cir(narrative: str) -> CIRSpecification:
    """
    Core Domain Service: Transforms natural language into CIR via LLM.
    """
    cir_schema = CIRSpecification.model_json_schema()
    
    system_prompt = (
        "You are an expert Cyber Security Architect. "
        "Analyze the provided attack scenario and map it to MITRE ATT&CK techniques. "
        "Output the result as a strict CIR JSON. Do not invent techniques."
    )

    try:
        response = await client.chat.completions.create(
            model="gpt-4o", # Pastikan model ini tersedia di SumoPod
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": narrative}
            ],
            tools=[{
                "type": "function",
                "function": {
                    "name": "generate_cir",
                    "description": "Generate CIR graph",
                    "parameters": cir_schema
                }
            }],
            tool_choice={"type": "function", "function": {"name": "generate_cir"}}
        )

        raw_args = response.choices[0].message.tool_calls[0].function.arguments
        parsed_data = json.loads(raw_args)
        
        # Log hasil parsing untuk debugging
        logger.info(f"Successfully parsed narrative: {parsed_data}")
        
        return CIRSpecification(**parsed_data)

    except Exception as e:
        logger.error(f"Error calling LLM: {str(e)}")
        # Jika gagal, jangan balik ke "phishing", tapi beri tahu backend terjadi error
        raise Exception(f"Gagal memproses AI: {str(e)}")