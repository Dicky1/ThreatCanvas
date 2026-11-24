"""Purple team loop: CIR -> Atomic Red Team / Caldera plan -> execution
results -> which scenario techniques the generated rules actually detected.

ThreatCanvas never executes anything itself. It exports:
- an Invoke-AtomicRedTeam PowerShell script, and
- a Caldera bundle (abilities + adversary profile). Caldera's atomic plugin
  derives ability ids from an MD5 of each test's YAML, so ART GUIDs cannot be
  referenced directly; the bundle ships its own abilities (deterministic
  UUIDs) that call Invoke-AtomicTest on the agent.

After the analyst runs the plan in a lab, they upload the telemetry captured
during execution (a detection dataset) and optionally the execution log
(Invoke-AtomicTest CSV or Caldera operation report JSON).
"""

from __future__ import annotations

import csv
import io
import json
import re
import uuid
import zipfile
from dataclasses import dataclass, field
from datetime import UTC, datetime
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

from app.schemas.cir import CIRSpecification
from app.services.attack_knowledge import TACTIC_NAMES

ATOMIC_INDEX_PATH = Path(__file__).parents[1] / "data" / "atomic_index.json"
GUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
TECHNIQUE_RE = re.compile(r"^T\d{4}(\.\d{3})?$")
PLATFORMS = ("windows", "linux", "macos")
_NAMESPACE = uuid.UUID("0f8b2a9e-5d1c-4b6a-9e3f-7c2d1a0b9e44")
MAX_EXECUTION_LOG_BYTES = 5 * 1024 * 1024


class PurpleTeamError(ValueError):
    pass


@lru_cache(maxsize=1)
def atomic_index() -> dict[str, list[dict[str, Any]]]:
    with ATOMIC_INDEX_PATH.open(encoding="utf-8") as stream:
        return json.load(stream)["techniques"]


@dataclass
class PlanStep:
    step_id: str
    technique: str
    technique_name: str | None
    tactic: str
    tests: list[dict[str, Any]] = field(default_factory=list)
    from_parent: bool = False


def build_plan(cir: CIRSpecification, platform: str = "windows") -> list[PlanStep]:
    if platform not in PLATFORMS:
        raise PurpleTeamError(f"platform must be one of: {', '.join(PLATFORMS)}")
    index = atomic_index()
    steps: list[PlanStep] = []
    for node in cir.attack_graph.nodes:
        technique = str(node.technique).upper()
        tests = [t for t in index.get(technique, []) if platform in t["platforms"]]
        from_parent = False
        if not tests and "." in technique:
            # No atomic for the sub-technique: offer the parent's tests.
            tests = [t for t in index.get(technique.split(".")[0], []) if platform in t["platforms"]]
            from_parent = bool(tests)
        steps.append(PlanStep(node.step_id, technique, node.technique_name, node.tactic, tests, from_parent))
    return steps


def _select(plan: list[PlanStep], test_guids: list[str] | None) -> list[tuple[PlanStep, dict[str, Any]]]:
    """Chosen tests in scenario order. Unknown GUIDs are rejected; by default
    the first test of every step is used. A test shared by several steps is
    run once."""
    wanted = None if test_guids is None else {g.lower() for g in test_guids}
    if wanted is not None:
        invalid = [g for g in wanted if not GUID_RE.match(g)]
        if invalid:
            raise PurpleTeamError(f"Invalid test GUID(s): {', '.join(sorted(invalid))}")
        available = {t["guid"] for step in plan for t in step.tests}
        unknown = wanted - available
        if unknown:
            raise PurpleTeamError(f"Test GUID(s) not in this scenario's plan: {', '.join(sorted(unknown))}")
    selected, seen = [], set()
    for step in plan:
        tests = step.tests if wanted is not None else step.tests[:1]
        for test in tests:
            if (wanted is None or test["guid"] in wanted) and test["guid"] not in seen:
                seen.add(test["guid"])
                selected.append((step, test))
    if not selected:
        raise PurpleTeamError("No atomic tests selected for this scenario and platform")
    return selected


def _ps_quote(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def render_invoke_atomic(cir: CIRSpecification, plan: list[PlanStep], test_guids: list[str] | None) -> str:
    selected = _select(plan, test_guids)
    rows = ",\n".join(
        f"    @{{ Step = {_ps_quote(step.step_id)}; Technique = {_ps_quote(step.technique if not step.from_parent else step.technique.split('.')[0])}; "
        f"Guid = {_ps_quote(test['guid'])}; Name = {_ps_quote(test['name'])} }}"
        for step, test in selected
    )
    scenario = re.sub(r"[\r\n]", " ", cir.scenario_id)[:120]
    return f"""# ThreatCanvas purple team plan - scenario {scenario}
# Generated {datetime.now(UTC).strftime('%Y-%m-%d %H:%M UTC')}
#
# RUN ONLY IN AN ISOLATED LAB YOU ARE AUTHORIZED TO TEST.
# Requires Invoke-AtomicRedTeam: https://github.com/redcanaryco/invoke-atomicredteam
# Collect Sysmon / Windows event logs while this runs, then upload them and
# the execution log below to ThreatCanvas (Purple Team > Import results).

#Requires -Version 5.1
param(
    [string]$ExecutionLogPath = (Join-Path $PSScriptRoot 'threatcanvas-execution-log.csv'),
    [switch]$Cleanup
)
Import-Module Invoke-AtomicRedTeam -ErrorAction Stop

$tests = @(
{rows}
)

foreach ($test in $tests) {{
    Write-Host "[$($test.Step)] $($test.Technique) - $($test.Name)"
    if ($Cleanup) {{
        Invoke-AtomicTest $test.Technique -TestGuids $test.Guid -Cleanup
        continue
    }}
    Invoke-AtomicTest $test.Technique -TestGuids $test.Guid -GetPrereqs
    Invoke-AtomicTest $test.Technique -TestGuids $test.Guid -ExecutionLogPath $ExecutionLogPath
}}
"""


def _caldera_tactic(tactic_id: str) -> str:
    return TACTIC_NAMES.get(tactic_id.upper(), "execution").lower().replace(" ", "-")


def render_caldera_bundle(cir: CIRSpecification, plan: list[PlanStep], test_guids: list[str] | None, platform: str) -> bytes:
    selected = _select(plan, test_guids)
    adversary_id = str(uuid.uuid5(_NAMESPACE, f"adversary:{cir.scenario_id}:{platform}"))
    ability_ids = []
    files: dict[str, str] = {}
    for step, test in selected:
        technique = step.technique if not step.from_parent else step.technique.split(".")[0]
        ability_id = str(uuid.uuid5(_NAMESPACE, f"ability:{test['guid']}:{platform}"))
        ability_ids.append(ability_id)
        run = f"Invoke-AtomicTest {technique} -TestGuids {test['guid']}"
        if platform == "windows":
            executors = {"psh": {"command": f"{run} -GetPrereqs; {run}", "cleanup": f"{run} -Cleanup"}}
            caldera_platform = "windows"
        else:
            executors = {"sh": {
                "command": f"pwsh -NoProfile -Command \"{run} -GetPrereqs; {run}\"",
                "cleanup": f"pwsh -NoProfile -Command \"{run} -Cleanup\"",
            }}
            caldera_platform = "darwin" if platform == "macos" else "linux"
        tactic = _caldera_tactic(step.tactic)
        ability = [{
            "id": ability_id,
            "name": f"[ART] {test['name']}"[:200],
            "description": f"Atomic Red Team test {test['guid']} via Invoke-AtomicRedTeam (ThreatCanvas step {step.step_id}).",
            "tactic": tactic,
            "technique": {"attack_id": technique, "name": step.technique_name or technique},
            "platforms": {caldera_platform: executors},
        }]
        files[f"abilities/{tactic}/{ability_id}.yml"] = yaml.safe_dump(ability, sort_keys=False, allow_unicode=True)
    adversary = {
        "id": adversary_id,
        "name": f"ThreatCanvas - {cir.scenario_id}"[:200],
        "description": "Generated by ThreatCanvas from a CIR attack graph. Requires Invoke-AtomicRedTeam on the agent.",
        "atomic_ordering": ability_ids,
        "tags": ["threatcanvas", "atomic-red-team"],
    }
    files[f"adversaries/{adversary_id}.yml"] = yaml.safe_dump(adversary, sort_keys=False, allow_unicode=True)
    files["README.txt"] = (
        "ThreatCanvas Caldera bundle\n\n"
        "Copy abilities/ and adversaries/ into a Caldera plugin data directory\n"
        "(e.g. plugins/stockpile/data/), restart Caldera, then run the adversary\n"
        f"'{adversary['name']}' against agents that have Invoke-AtomicRedTeam installed.\n"
        "Run only in an isolated lab you are authorized to test.\n"
    )
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, content in files.items():
            archive.writestr(name, content)
    return buffer.getvalue()


# --- execution logs --------------------------------------------------------------

@dataclass
class Execution:
    technique: str
    guid: str | None
    name: str | None
    succeeded: bool
    timestamp: str | None = None


def parse_execution_log(filename: str, data: bytes) -> list[Execution]:
    """Invoke-AtomicTest CSV log or a Caldera operation report (JSON)."""
    if len(data) > MAX_EXECUTION_LOG_BYTES:
        raise PurpleTeamError("Execution log exceeds 5 MB")
    text = data.decode("utf-8-sig", errors="replace")
    if filename.lower().endswith(".json") or text.lstrip().startswith(("{", "[")):
        try:
            return _caldera_report(json.loads(text))
        except json.JSONDecodeError as error:
            raise PurpleTeamError("Execution log is not valid JSON") from error
    reader = csv.DictReader(io.StringIO(text))
    if not reader.fieldnames or "Technique" not in reader.fieldnames:
        raise PurpleTeamError("CSV must be an Invoke-AtomicTest execution log (needs a 'Technique' column)")
    executions = []
    for row in reader:
        technique = (row.get("Technique") or "").strip().upper()
        if not TECHNIQUE_RE.match(technique):
            continue
        exit_code = (row.get("ExitCode") or "").strip()
        executions.append(Execution(
            technique=technique,
            guid=(row.get("GUID") or "").strip().lower() or None,
            name=(row.get("Test Name") or "").strip() or None,
            succeeded=exit_code in ("", "0"),
            timestamp=(row.get("Execution Time (UTC)") or "").strip() or None,
        ))
    return executions


def _caldera_report(document: Any) -> list[Execution]:
    executions: list[Execution] = []

    def walk(node: Any, depth: int = 0) -> None:
        if depth > 12:
            return
        if isinstance(node, dict):
            attack = node.get("attack") if isinstance(node.get("attack"), dict) else {}
            technique = str(attack.get("technique_id") or node.get("technique_id") or "").upper()
            if TECHNIQUE_RE.match(technique) and ("status" in node or "run" in node):
                status = node.get("status")
                executions.append(Execution(
                    technique=technique,
                    guid=None,
                    name=str(node.get("ability_name") or node.get("name") or "") or None,
                    succeeded=status in (0, "0", None, "success"),
                    timestamp=str(node.get("run") or node.get("finish") or "") or None,
                ))
                return
            for value in node.values():
                walk(value, depth + 1)
        elif isinstance(node, list):
            for value in node:
                walk(value, depth + 1)

    walk(document)
    if not executions:
        raise PurpleTeamError("No executed techniques found in the Caldera report")
    return executions


# --- results ---------------------------------------------------------------------

def _same_technique(a: str, b: str) -> bool:
    return a == b or a.split(".")[0] == b.split(".")[0]


def technique_results(
    cir: CIRSpecification,
    evaluation: dict[str, Any],
    executions: list[Execution] | None,
) -> dict[str, Any]:
    """Join scenario techniques with rule hits and (optional) execution log."""
    rows = []
    seen = set()
    for node in cir.attack_graph.nodes:
        technique = str(node.technique).upper()
        if technique in seen:
            continue
        seen.add(technique)
        rules = [r for r in evaluation["rules"] if any(_same_technique(t, technique) for t in r["techniques"])]
        alerts = sum(r["malicious_hits"] + r["benign_hits"] for r in rules if not r["error"])
        executed: bool | None = None
        if executions is not None:
            executed = any(e.succeeded and _same_technique(e.technique, technique) for e in executions)
        if not rules:
            status = "NO_RULE"
        elif executed is False:
            status = "NOT_EXECUTED"  # alerts without a successful execution are not credited
        elif alerts > 0:
            status = "DETECTED"
        elif executed:
            status = "MISSED"
        else:
            status = "UNVERIFIED"
        rows.append({
            "technique": technique,
            "technique_name": node.technique_name,
            "tactic": node.tactic,
            "rules": len(rules),
            "alerts": alerts,
            "executed": executed,
            "status": status,
        })
    executed_rows = [r for r in rows if r["executed"] is not False]
    with_rules = [r for r in executed_rows if r["rules"]]
    detected = sum(1 for r in rows if r["status"] == "DETECTED")
    return {
        "techniques": rows,
        "summary": {
            "techniques": len(rows),
            "detected": detected,
            "missed": sum(1 for r in rows if r["status"] == "MISSED"),
            "no_rule": sum(1 for r in rows if r["status"] == "NO_RULE"),
            "not_executed": sum(1 for r in rows if r["status"] == "NOT_EXECUTED"),
            "unverified": sum(1 for r in rows if r["status"] == "UNVERIFIED"),
            "detection_rate": round(detected / len(with_rules), 4) if with_rules else None,
            "execution_log": executions is not None,
            "executions": len(executions or []),
        },
    }
