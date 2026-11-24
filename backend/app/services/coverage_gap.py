"""Gap analysis against the organisation's real state (DeTT&CT-style):
which scenario techniques are covered by rules the organisation already
runs, and whether the telemetry those detections need is collected."""

from __future__ import annotations

import csv
import io
import re
import zipfile
from dataclasses import dataclass, field
from typing import Any

import yaml

from app.schemas.cir import CIRSpecification
from app.services.attack_knowledge import ATTACKKnowledgeService

MAX_RULE_FILE_BYTES = 30 * 1024 * 1024
MAX_UNCOMPRESSED_BYTES = 150 * 1024 * 1024
MAX_RULES = 10_000
MAX_ARCHIVE_MEMBERS = 10_000
TECHNIQUE_TAG_RE = re.compile(r"^attack\.(t\d{4}(?:[._]\d{3})?)$", re.IGNORECASE)
TECHNIQUE_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.IGNORECASE)


class InventoryError(ValueError):
    pass


@dataclass
class ParsedRule:
    title: str
    rule_id: str | None
    techniques: list[str]
    logsource: dict[str, Any] | None
    status: str | None
    level: str | None
    source: str
    source_file: str


@dataclass
class InventoryParseResult:
    rules: list[ParsedRule] = field(default_factory=list)
    skipped: int = 0
    errors: list[str] = field(default_factory=list)


def _sigma_rules(text: str, source_file: str, result: InventoryParseResult) -> None:
    try:
        documents = list(yaml.safe_load_all(text))
    except yaml.YAMLError:
        result.errors.append(f"{source_file}: invalid YAML")
        return
    for document in documents:
        if not isinstance(document, dict) or "detection" not in document:
            continue
        techniques = []
        for tag in document.get("tags") or []:
            match = TECHNIQUE_TAG_RE.match(str(tag).strip())
            if match:
                technique = match.group(1).upper().replace("_", ".")
                if technique not in techniques:
                    techniques.append(technique)
        if not techniques:
            result.skipped += 1  # rules without ATT&CK tags cannot be mapped
            continue
        logsource = document.get("logsource") if isinstance(document.get("logsource"), dict) else None
        result.rules.append(ParsedRule(
            title=str(document.get("title") or "untitled")[:300],
            rule_id=str(document.get("id"))[:100] if document.get("id") else None,
            techniques=techniques,
            logsource={k: str(v)[:100] for k, v in (logsource or {}).items() if k in {"product", "category", "service"}} or None,
            status=str(document.get("status"))[:30] if document.get("status") else None,
            level=str(document.get("level"))[:30] if document.get("level") else None,
            source="sigma",
            source_file=source_file[:300],
        ))


def _csv_rules(text: str, source_file: str, result: InventoryParseResult) -> None:
    reader = csv.DictReader(io.StringIO(text))
    fields = {name.lower().strip(): name for name in reader.fieldnames or []}
    technique_col = next((fields[k] for k in ("technique", "techniques", "technique_id", "mitre", "attack") if k in fields), None)
    title_col = next((fields[k] for k in ("title", "name", "rule", "rule_name") if k in fields), None)
    if not technique_col:
        raise InventoryError("CSV needs a 'technique' column (and ideally 'title')")
    for row in reader:
        techniques = list(dict.fromkeys(t.upper() for t in TECHNIQUE_RE.findall(row.get(technique_col) or "")))
        if not techniques:
            result.skipped += 1
            continue
        result.rules.append(ParsedRule(
            title=str(row.get(title_col) or "untitled")[:300] if title_col else "untitled",
            rule_id=None,
            techniques=techniques,
            logsource=None,
            status=None,
            level=None,
            source="csv",
            source_file=source_file[:300],
        ))


def parse_rule_inventory(filename: str, data: bytes) -> InventoryParseResult:
    """Sigma .yml/.yaml (single or multi-document), a .zip of a rules folder,
    or a CSV export (technique, title) for rules in other formats."""
    if len(data) > MAX_RULE_FILE_BYTES:
        raise InventoryError(f"File exceeds {MAX_RULE_FILE_BYTES // (1024 * 1024)} MB")
    result = InventoryParseResult()
    lowered = filename.lower()
    if lowered.endswith(".zip"):
        try:
            archive = zipfile.ZipFile(io.BytesIO(data))
        except zipfile.BadZipFile as error:
            raise InventoryError("Invalid ZIP archive") from error
        members = [m for m in archive.infolist() if not m.is_dir()]
        if len(members) > MAX_ARCHIVE_MEMBERS:
            raise InventoryError("Archive contains too many files")
        budget = MAX_UNCOMPRESSED_BYTES
        for member in members:
            if not member.filename.lower().endswith((".yml", ".yaml", ".csv")):
                continue
            with archive.open(member) as stream:
                content = stream.read(budget + 1)
            budget -= len(content)
            if budget < 0:
                raise InventoryError("Archive is too large when uncompressed")
            text = content.decode("utf-8", errors="replace")
            if member.filename.lower().endswith(".csv"):
                _csv_rules(text, member.filename, result)
            else:
                _sigma_rules(text, member.filename, result)
            if len(result.rules) > MAX_RULES:
                raise InventoryError(f"More than {MAX_RULES} rules")
    elif lowered.endswith(".csv"):
        _csv_rules(data.decode("utf-8-sig", errors="replace"), filename, result)
    else:
        _sigma_rules(data.decode("utf-8", errors="replace"), filename, result)
    if len(result.rules) > MAX_RULES:
        raise InventoryError(f"More than {MAX_RULES} rules")
    if not result.rules:
        raise InventoryError(
            "No ATT&CK-tagged rules found. Sigma rules need tags like 'attack.t1059.001'; CSV needs a technique column."
        )
    return result


def parse_dettect(text: str, known_components: set[str]) -> tuple[list[str], list[str]]:
    """DeTT&CT data source administration YAML -> (available components, unmatched names).

    A data source counts as available when it is marked available for data
    analytics, or connected with a non-zero data quality score."""
    try:
        document = yaml.safe_load(text)
    except yaml.YAMLError as error:
        raise InventoryError("Invalid YAML") from error
    if not isinstance(document, dict) or not isinstance(document.get("data_sources"), list):
        raise InventoryError("Not a DeTT&CT data source administration file (missing 'data_sources')")
    lookup = {name.lower(): name for name in known_components}
    available, unmatched = [], []
    for entry in document["data_sources"]:
        if not isinstance(entry, dict) or not entry.get("data_source_name"):
            continue
        variants = entry.get("data_source") if isinstance(entry.get("data_source"), list) else [entry]
        usable = False
        for variant in variants:
            if not isinstance(variant, dict):
                continue
            quality = variant.get("data_quality") or {}
            scores = [v for v in quality.values() if isinstance(v, (int, float))] if isinstance(quality, dict) else []
            if variant.get("available_for_data_analytics") is True or (variant.get("date_connected") and any(s > 0 for s in scores)):
                usable = True
        if not usable:
            continue
        name = str(entry["data_source_name"]).strip()
        match = lookup.get(name.lower())
        if match:
            if match not in available:
                available.append(match)
        elif name not in unmatched:
            unmatched.append(name)
    return sorted(available), unmatched


def all_data_components(knowledge: ATTACKKnowledgeService) -> list[str]:
    names: set[str] = set()
    for technique in knowledge.techniques.values():
        if not technique.deprecated:
            names.update(technique.data_components)
    return sorted(names)


def _relation(rule_technique: str, technique: str) -> str | None:
    if rule_technique == technique:
        return "exact"
    if rule_technique.split(".")[0] == technique.split(".")[0]:
        return "related"  # parent <-> sub-technique
    return None


def analyze_gaps(
    cir: CIRSpecification,
    knowledge: ATTACKKnowledgeService,
    inventory: list[dict[str, Any]],
    available_components: list[str] | None,
    generated_rule_techniques: set[str],
) -> dict[str, Any]:
    available = set(available_components or [])
    profile_set = available_components is not None
    rows = []
    seen = set()
    missing_counter: dict[str, int] = {}
    for node in cir.attack_graph.nodes:
        technique = str(node.technique).upper()
        if technique in seen:
            continue
        seen.add(technique)
        resolved = knowledge.resolve_technique(technique)
        required = list(resolved.data_components) if resolved else []
        exact = [r for r in inventory if any(_relation(t, technique) == "exact" for t in r["techniques"])]
        related = [r for r in inventory if r not in exact and any(_relation(t, technique) for t in r["techniques"])]
        have = [c for c in required if c in available]
        missing = [c for c in required if c not in available] if profile_set else []
        has_rule = bool(exact or related)
        if not required or not profile_set:
            telemetry = None  # unknown: no mapping or no profile configured
        else:
            telemetry = bool(have)
        if has_rule and telemetry is not False:
            status = "COVERED" if telemetry else "COVERED_UNVERIFIED_TELEMETRY"
        elif has_rule:
            status = "RULE_WITHOUT_TELEMETRY"
        elif telemetry:
            status = "TELEMETRY_WITHOUT_RULE"
        elif telemetry is False:
            status = "BLIND"
        else:
            status = "NO_RULE"
        if status in ("BLIND", "RULE_WITHOUT_TELEMETRY"):
            for component in missing:
                missing_counter[component] = missing_counter.get(component, 0) + 1
        rows.append({
            "technique": technique,
            "technique_name": resolved.name if resolved else node.technique_name,
            "tactic": node.tactic,
            "status": status,
            "existing_rules": [{"title": r["title"], "match": "exact"} for r in exact[:10]]
            + [{"title": r["title"], "match": "related"} for r in related[:5]],
            "existing_rule_count": len(exact) + len(related),
            "generated_rule_available": technique in generated_rule_techniques,
            "required_data_components": required,
            "available_data_components": have,
            "missing_data_components": missing,
            "log_sources": list(resolved.log_sources) if resolved else [],
        })
    covered = sum(1 for r in rows if r["status"].startswith("COVERED"))
    return {
        "techniques": rows,
        "summary": {
            "techniques": len(rows),
            "covered": covered,
            "coverage": round(covered / len(rows), 4) if rows else None,
            "blind": sum(1 for r in rows if r["status"] == "BLIND"),
            "rule_without_telemetry": sum(1 for r in rows if r["status"] == "RULE_WITHOUT_TELEMETRY"),
            "telemetry_without_rule": sum(1 for r in rows if r["status"] == "TELEMETRY_WITHOUT_RULE"),
            "inventory_rules": len(inventory),
            "data_source_profile": profile_set,
        },
        # Collecting these would turn the most blind / unverifiable techniques into detectable ones.
        "top_missing_data_components": [
            {"data_component": name, "techniques": count}
            for name, count in sorted(missing_counter.items(), key=lambda item: (-item[1], item[0]))[:10]
        ],
    }


NAVIGATOR_COLORS = {
    "COVERED": "#31a354",
    "COVERED_UNVERIFIED_TELEMETRY": "#a1d99b",
    "RULE_WITHOUT_TELEMETRY": "#fdae6b",
    "TELEMETRY_WITHOUT_RULE": "#fee08b",
    "BLIND": "#de2d26",
    "NO_RULE": "#fc9272",
}


def navigator_layer(scenario_id: str, analysis: dict[str, Any], attack_major: str) -> dict[str, Any]:
    return {
        "name": f"ThreatCanvas gap analysis - {scenario_id}"[:120],
        "versions": {"attack": attack_major, "navigator": "4.9.1", "layer": "4.5"},
        "domain": "enterprise-attack",
        "description": "Scenario techniques coloured by real detection coverage (existing rules + collected data sources).",
        "techniques": [
            {
                "techniqueID": row["technique"],
                "color": NAVIGATOR_COLORS[row["status"]],
                "comment": f"{row['status']}; rules: {row['existing_rule_count']}; missing data: {', '.join(row['missing_data_components']) or '-'}"[:500],
                "enabled": True,
            }
            for row in analysis["techniques"]
        ],
        "legendItems": [{"label": label.replace("_", " ").title(), "color": color} for label, color in NAVIGATOR_COLORS.items()],
    }
