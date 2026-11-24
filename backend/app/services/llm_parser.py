import json
import logging
from dataclasses import dataclass, field

from pydantic import ValidationError

from app.schemas.cir import CIRSpecification
from app.services.llm_client import client_for, get_profile

# Setup logging agar kita tahu apa yang terjadi di balik layar
logger = logging.getLogger(__name__)



MAX_PREVIOUS_OUTPUT_CHARS = 20_000


class LLMUnavailableError(Exception):
    """The LLM provider could not be reached or rejected the request."""


class CIRGenerationError(Exception):
    """The LLM answered, but its output is not a schema-valid CIR."""

    def __init__(self, errors: list[str], raw_output: str):
        super().__init__("; ".join(errors))
        self.errors = errors
        self.raw_output = raw_output


@dataclass
class RepairContext:
    """Previous LLM output plus the errors it must fix."""

    previous_output: str
    errors: list[str] = field(default_factory=list)


def _schema_errors(error: ValidationError) -> list[str]:
    return [
        f"{'.'.join(str(part) for part in item['loc']) or '(root)'}: {item['msg']}"
        for item in error.errors()[:25]
    ]


def _strip_fences(text: str) -> str:
    """Some models wrap JSON in ```json fences even in JSON mode."""
    text = text.strip()
    if text.startswith("```"):
        text = text.split("\n", 1)[1] if "\n" in text else ""
        if text.rstrip().endswith("```"):
            text = text.rstrip()[:-3]
    return text.strip()


def _repair_message(repair: RepairContext) -> str:
    issues = "\n".join(f"- {error}" for error in repair.errors[:40])
    return (
        "Your previous CIR output failed validation with these errors:\n"
        f"{issues}\n\n"
        "Return the complete corrected CIR by calling generate_cir again. "
        "Fix only what the errors require; keep every attack step from the "
        "narrative, keep their order, and do not invent new steps."
    )


async def parse_narrative_to_cir(
    narrative: str,
    *,
    repair: RepairContext | None = None,
    instructions: str | None = None,
    profile: str | None = None,
) -> CIRSpecification:
    """
    Core Domain Service: Transforms natural language into CIR via LLM.

    With ``repair`` the previous output and its validation errors are sent
    back so the model can correct them (self-repair loop).

    Raises LLMUnavailableError when the provider call fails and
    CIRGenerationError when the answer is not a schema-valid CIR.
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
TA0040 (Impact)
TA0042 (Resource Development)
TA0043 (Reconnaissance)
TA0112 (Defense Impairment)

Note: in current ATT&CK, TA0005 is named "Stealth" (formerly Defense Evasion).

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

CIR v2 Entities

When the narrative provides enough information, populate the optional top-level
entities array with typed entities using these entity_type values:
threat_actor, technique, tactic, asset, identity, vulnerability, observable,
detection_rule, defensive_control, trust_zone, evidence.

Use entity_refs on nodes to link a node to entity IDs. Keep the legacy node
fields populated as well. Use uppercase relationships when applicable:
USES, TARGETS, REQUIRES, EXPLOITS, PRODUCES, DETECTED_BY, COUNTERED_BY,
CONNECTED_TO.

Confidence is a number from 0 to 1. Provenance and timestamps are optional.

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
    messages = [{"role": "system", "content": system_prompt}]
    if instructions:
        # Source-specific guidance (e.g. "this is a CTI report"); still a server-side prompt.
        messages.append({"role": "system", "content": instructions})
    messages.append({"role": "user", "content": narrative})
    if repair is not None:
        messages.append({"role": "assistant", "content": repair.previous_output[:MAX_PREVIOUS_OUTPUT_CHARS]})
        messages.append({"role": "user", "content": _repair_message(repair)})

    llm = get_profile(profile)
    request: dict = {"model": llm.model, "messages": messages}
    if llm.mode == "json":
        # Models without reliable tool calling: ask for a JSON object that
        # follows the schema instead.
        messages.insert(1, {
            "role": "system",
            "content": "Respond with ONLY a JSON object (no prose, no markdown) that conforms to this JSON Schema:\n"
            + json.dumps(cir_schema, separators=(",", ":")),
        })
        request["response_format"] = {"type": "json_object"}
    else:
        request["tools"] = [{
            "type": "function",
            "function": {"name": "generate_cir", "description": "Generate CIR graph", "parameters": cir_schema},
        }]
        request["tool_choice"] = {"type": "function", "function": {"name": "generate_cir"}}

    try:
        response = await client_for(llm).chat.completions.create(**request)
    except Exception as error:
        logger.error("Error calling LLM profile %s: %s", llm.name, error)
        raise LLMUnavailableError("LLM provider request failed") from error

    try:
        if llm.mode == "json":
            raw_args = _strip_fences(response.choices[0].message.content or "")
        else:
            raw_args = response.choices[0].message.tool_calls[0].function.arguments
    except (AttributeError, IndexError, TypeError) as error:
        raise CIRGenerationError(["Model did not return a CIR (no tool call / content)"], "") from error

    try:
        parsed_data = json.loads(raw_args)
    except json.JSONDecodeError as error:
        raise CIRGenerationError([f"Output is not valid JSON: {error.msg}"], raw_args) from error

    try:
        cir = CIRSpecification(**parsed_data)
    except ValidationError as error:
        raise CIRGenerationError(_schema_errors(error), raw_args) from error
    except TypeError as error:
        raise CIRGenerationError(["Output must be a JSON object"], raw_args) from error

    logger.debug("Parsed narrative into %d CIR nodes", len(cir.attack_graph.nodes))
    return cir
