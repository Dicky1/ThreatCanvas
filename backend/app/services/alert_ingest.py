"""SIEM / EDR alerts -> CIR attack graph (SOC triage).

Alerts carrying ATT&CK technique ids (Wazuh rule.mitre.id, Elastic
kibana.alert.rule.threat / ECS threat.technique, Microsoft Sentinel /
Defender Techniques / AttackTechniques, Splunk ES annotations, Sigma-style
attack.tXXXX tags, ...) are converted deterministically: ordered by time,
one node per (technique, host) run, evidence from the alert fields. Alerts
without techniques can optionally be summarised for the LLM pipeline.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from app.schemas.cir import CIRSpecification
from app.services.attack_knowledge import ATTACKKnowledgeService

MAX_ALERTS = 5_000
MAX_EVIDENCE_PER_NODE = 5
TECHNIQUE_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.IGNORECASE)
TAG_RE = re.compile(r"\battack\.(t\d{4}(?:[._]\d{3})?)\b", re.IGNORECASE)
TECHNIQUE_KEY_HINTS = ("technique", "mitre", "attack", "tags", "annotations")

TIME_KEYS = ("@timestamp", "timestamp", "TimeGenerated", "_time", "time", "detect_time", "kibana.alert.original_time",
             "data.win.system.systemTime", "EventTime", "UtcTime", "event.created", "FirstActivity", "StartTime")
HOST_KEYS = ("host.name", "agent.name", "DeviceName", "Computer", "hostname", "Hostname", "host.hostname", "dest",
             "dvc", "ComputerName", "dest_host", "src_host", "host")
TITLE_KEYS = ("rule.description", "kibana.alert.rule.name", "AlertName", "Title", "search_name", "rule.name",
              "signature", "title", "DisplayName", "name", "message")
USER_KEYS = ("user.name", "AccountName", "data.win.eventdata.user", "user", "User", "src_user")
EVIDENCE_KEYS = {
    "command_line": ("process.command_line", "data.win.eventdata.commandLine", "ProcessCommandLine", "CommandLine", "cmdline", "process"),
    "image": ("process.executable", "data.win.eventdata.image", "FolderPath", "Image", "process_path", "NewProcessName"),
    "ip": ("destination.ip", "data.win.eventdata.destinationIp", "RemoteIP", "dest_ip", "DestinationIp", "dst_ip"),
    "domain": ("dns.question.name", "url.domain", "QueryName", "DestinationHostname", "query"),
    "url": ("url.full", "RemoteUrl", "url"),
    "hash_sha256": ("process.hash.sha256", "file.hash.sha256", "SHA256", "sha256"),
    "filename": ("file.path", "TargetFilename", "FileName", "file_path", "data.win.eventdata.targetFilename"),
    "registry_key": ("registry.path", "RegistryKey", "TargetObject", "data.win.eventdata.targetObject"),
}


class AlertIngestError(ValueError):
    pass


@dataclass
class Alert:
    index: int
    timestamp: str | None
    host: str | None
    user: str | None
    title: str
    techniques: list[str]
    evidence: dict[str, str]
    raw_keys: int = 0


@dataclass
class AlertConversion:
    cir: CIRSpecification | None
    alerts: list[Alert]
    used_alerts: int = 0
    skipped_techniques: list[str] = field(default_factory=list)


def _walk(value: Any, path: str = "", depth: int = 0) -> Iterator[tuple[str, Any]]:
    """Yield (dotted path without list indices, scalar value)."""
    if depth > 10:
        return
    if isinstance(value, dict):
        for key, item in value.items():
            yield from _walk(item, f"{path}.{key}" if path else str(key), depth + 1)
    elif isinstance(value, list):
        for item in value[:200]:
            yield from _walk(item, path, depth + 1)
    elif value is not None and value != "":
        yield path, value


def _unwrap(document: Any) -> Iterator[dict[str, Any]]:
    if isinstance(document, list):
        for item in document:
            yield from _unwrap(item)
        return
    if not isinstance(document, dict):
        return
    if isinstance(document.get("result"), dict):  # Splunk JSON export
        yield document["result"]
    elif isinstance(document.get("_source"), dict):  # Elastic hit
        yield document["_source"]
    elif isinstance(document.get("hits"), dict) and isinstance(document["hits"].get("hits"), list):
        yield from _unwrap(document["hits"]["hits"])
    elif isinstance(document.get("value"), list):  # Microsoft Graph / Sentinel API
        yield from _unwrap(document["value"])
    elif isinstance(document.get("alerts"), list) and len(document) <= 3:
        yield from _unwrap(document["alerts"])
    else:
        yield document


def load_alert_documents(data: bytes) -> list[dict[str, Any]]:
    text = data.decode("utf-8-sig", errors="replace").strip()
    if not text:
        raise AlertIngestError("The file is empty")
    try:
        documents = list(_unwrap(json.loads(text)))
    except json.JSONDecodeError:
        documents = []
        for number, line in enumerate(text.splitlines(), start=1):
            line = line.strip()
            if not line:
                continue
            try:
                documents.extend(_unwrap(json.loads(line)))
            except json.JSONDecodeError as error:
                raise AlertIngestError(f"Line {number} is not valid JSON (expected JSON, JSON lines or NDJSON)") from error
    if not documents:
        raise AlertIngestError("No alerts found in the file")
    if len(documents) > MAX_ALERTS:
        raise AlertIngestError(f"More than {MAX_ALERTS} alerts; export a narrower time range")
    return documents


def _first(flat: list[tuple[str, Any]], keys: tuple[str, ...]) -> str | None:
    lowered = {}
    for path, value in flat:
        lowered.setdefault(path.lower(), value)
    for key in keys:
        value = lowered.get(key.lower())
        if value is not None and not isinstance(value, (dict, list)):
            text = str(value).strip()
            if text:
                return text[:2000]
    return None


def parse_alert(index: int, document: dict[str, Any]) -> Alert:
    flat = list(_walk(document))
    techniques: list[str] = []
    for path, value in flat:
        text = str(value)
        lowered_path = path.lower()
        if any(hint in lowered_path for hint in TECHNIQUE_KEY_HINTS):
            found = TECHNIQUE_RE.findall(text)
            found += [m.replace("_", ".") for m in TAG_RE.findall(text)]
            for technique in found:
                technique = technique.upper()
                if technique not in techniques:
                    techniques.append(technique)
    evidence = {name: value for name, keys in EVIDENCE_KEYS.items() if (value := _first(flat, keys))}
    return Alert(
        index=index,
        timestamp=_first(flat, TIME_KEYS),
        host=_first(flat, HOST_KEYS),
        user=_first(flat, USER_KEYS),
        title=(_first(flat, TITLE_KEYS) or f"Alert {index + 1}")[:200],
        techniques=techniques,
        evidence=evidence,
        raw_keys=len(flat),
    )


def _sort_key(alert: Alert) -> tuple[int, str, int]:
    return (0 if alert.timestamp else 1, alert.timestamp or "", alert.index)


def _evidence(alert: Alert) -> dict[str, Any]:
    kind = (
        "process" if "command_line" in alert.evidence or "image" in alert.evidence
        else "network" if {"ip", "domain", "url"} & alert.evidence.keys()
        else "registry" if "registry_key" in alert.evidence
        else "file" if "filename" in alert.evidence or "hash_sha256" in alert.evidence
        else "alert"
    )
    item: dict[str, Any] = {
        "type": kind,
        "description": alert.title,
        "source": "SIEM alert",
        "telemetry_source": "SIEM alert",
        "asset": alert.host,
        "validation_state": "UNVERIFIED",
        **{key: value for key, value in alert.evidence.items()},
    }
    if alert.timestamp:
        try:
            item["observed_at"] = datetime.fromisoformat(alert.timestamp.replace("Z", "+00:00")).isoformat()
        except ValueError:
            pass
    return item


def alerts_to_cir(documents: list[dict[str, Any]], knowledge: ATTACKKnowledgeService) -> AlertConversion:
    alerts = sorted((parse_alert(i, doc) for i, doc in enumerate(documents)), key=_sort_key)
    nodes: list[dict[str, Any]] = []
    skipped: list[str] = []
    used = 0
    last_key: tuple[str, str] | None = None
    for alert in alerts:
        known = []
        for technique in alert.techniques:
            resolved = knowledge.resolve_technique(technique)
            if resolved is None or resolved.deprecated or not resolved.tactics:
                if technique not in skipped:
                    skipped.append(technique)
                continue
            known.append(resolved)
        if not known:
            continue
        used += 1
        for resolved in known:
            key = (resolved.technique_id, (alert.host or "").lower())
            if key == last_key and nodes:
                node = nodes[-1]
                if len(node["evidence"]) < MAX_EVIDENCE_PER_NODE:
                    node["evidence"].append(_evidence(alert))
                continue
            last_key = key
            nodes.append({
                "step_id": f"a{len(nodes) + 1}",
                "tactic": resolved.tactics[0],
                "technique": resolved.technique_id,
                "target": alert.host or "unknown host",
                "actor": None,
                "action_type": alert.title[:80],
                "evidence": [_evidence(alert)],
                "provenance": "siem-alert",
                "confidence": 0.8,
            })
    if not nodes:
        return AlertConversion(None, alerts, used, skipped)
    cir = CIRSpecification(
        scenario_id=f"alerts-{datetime.now(UTC).strftime('%Y%m%d-%H%M%S')}",
        attack_graph={
            "nodes": nodes,
            "edges": [
                {"from": nodes[i]["step_id"], "to": nodes[i + 1]["step_id"], "relationship": "FOLLOWED_BY"}
                for i in range(len(nodes) - 1)
            ],
        },
        provenance="siem-alerts",
    )
    return AlertConversion(cir, alerts, used, skipped)


def alerts_narrative(alerts: list[Alert], limit: int = 150) -> str:
    """Compact, chronological alert digest for the LLM fallback."""
    lines = []
    for alert in sorted(alerts, key=_sort_key)[:limit]:
        details = "; ".join(f"{k}={v[:200]}" for k, v in alert.evidence.items())
        lines.append(
            f"- [{alert.timestamp or 'unknown time'}] host={alert.host or '?'} user={alert.user or '?'}: "
            f"{alert.title}{' | ' + details if details else ''}"
        )
    if len(alerts) > limit:
        lines.append(f"- ... {len(alerts) - limit} more alerts omitted")
    return "\n".join(lines)


ALERT_LLM_INSTRUCTIONS = (
    "The user message is a chronological digest of SIEM/EDR alerts from one incident, not a narrative. "
    "Reconstruct the attack chain they evidence: one node per distinct attacker step, in time order, "
    "using each alert's host as target and its fields (command line, image, IP, domain, hash, registry key, "
    "file) as structured evidence. Ignore alerts that are clearly benign noise. Do not invent steps "
    "that no alert supports."
)

CTI_LLM_INSTRUCTIONS = (
    "The user message is the text of a threat intelligence report (vendor blog, advisory or PDF). "
    "Extract only the attack chain it describes: the adversary's steps in chronological order, with the "
    "named threat actor (if any) as actor, the affected asset types as targets, and concrete IOCs / "
    "commands / file names / registry keys / domains from the report as structured evidence. Ignore "
    "marketing text, mitigations, detection advice and unrelated background."
)
