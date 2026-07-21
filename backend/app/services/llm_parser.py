import json
import uuid
import logging
from openai import AsyncOpenAI
from app.schemas.cir import CIRSpecification
from app.core.config import settings

# Setup logging agar kita tahu apa yang terjadi di balik layar
logger = logging.getLogger(__name__)

client = AsyncOpenAI(api_key=settings.OPENAI_API_KEY, base_url=settings.OPENAI_API_BASE)


async def parse_narrative_to_cir(narrative: str) -> CIRSpecification:
    """
    Core Domain Service: Transforms natural language into CIR via LLM.
    """
    cir_schema = CIRSpecification.model_json_schema()

    system_prompt = """
You are ThreatCanvas CIR Engine.

Your task is to convert a natural language cyber attack narrative into a valid
Cyber Incident Representation (CIR) JSON.

STRICT RULES

1. Output ONLY valid JSON matching the provided schema.
2. Never explain your answer.
3. Never add markdown.
4. Never omit required fields.
5. Never invent attack steps.
6. Preserve attack order exactly as described.

MITRE ATT&CK RULES

- tactic MUST always be MITRE ATT&CK Tactic ID.

Example:

TA0001
TA0002
TA0003
TA0004
TA0005
TA0006
TA0007
TA0008
TA0009
TA0010
TA0011

NEVER output

Initial Access
Execution
Persistence

------------------------------------------------

technique MUST always be MITRE Technique ID.

Examples

T1566.001
T1204
T1059.001
T1053.005
T1112
T1003.001
T1021.002
T1486

NEVER output

Spearphishing Attachment
User Execution
PowerShell
Scheduled Task
Registry Modification
Credential Dumping

------------------------------------------------

Evidence Rules

Every node MUST contain at least one evidence object.

Evidence.description MUST summarize the observable artifact.

Example

{
  "type":"command",
  "description":"PowerShell executed Invoke-Expression"
}

------------------------------------------------

Graph Rules

Every attack step becomes one node.

Nodes must be connected sequentially.

If there are N nodes there should normally be N-1 edges.

------------------------------------------------

Actor

Only populate actor if explicitly mentioned.

Otherwise null.

------------------------------------------------

Target

Always infer the attacked asset.

------------------------------------------------

Action Type

Use a concise verb.

Examples

Email Delivery
Execution
Persistence
Credential Dumping
Lateral Movement
Command and Control
Encryption

------------------------------------------------

Return ONLY JSON.
"""
    try:
        response = await client.chat.completions.create(
            model="gpt-4o",  # Pastikan model ini tersedia di SumoPod
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": narrative},
            ],
            tools=[
                {
                    "type": "function",
                    "function": {
                        "name": "generate_cir",
                        "description": "Generate CIR graph",
                        "parameters": cir_schema,
                    },
                }
            ],
            tool_choice={"type": "function", "function": {"name": "generate_cir"}},
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
