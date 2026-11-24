"""Converts Sigma rules to SIEM queries.

Splunk, Microsoft Defender XDR / Sentinel (KQL) and Elastic (Lucene) use the
official pySigma backends and processing pipelines. pySigma has no Wazuh
backend, so Wazuh XML rules are generated here for the subset of Sigma that
maps onto Wazuh's windows eventchannel decoder (field matches, AND within a
selection, OR across selections).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any
from xml.sax.saxutils import escape

import yaml
from sigma.backends.elasticsearch import LuceneBackend
from sigma.backends.kusto import KustoBackend
from sigma.backends.splunk import SplunkBackend
from sigma.collection import SigmaCollection
from sigma.exceptions import SigmaError
from sigma.pipelines.elasticsearch.windows import ecs_windows
from sigma.pipelines.microsoftxdr import microsoft_xdr_pipeline
from sigma.pipelines.splunk import splunk_windows_pipeline
from sigma.pipelines.sysmon import sysmon_pipeline

MAX_SIGMA_CHARS = 200_000


@dataclass(frozen=True)
class Target:
    key: str
    label: str
    language: str
    description: str


TARGETS: dict[str, Target] = {
    "splunk": Target("splunk", "Splunk (SPL)", "spl", "Sysmon data in Splunk via pySigma Splunk backend"),
    "kql": Target("kql", "Microsoft Defender XDR / Sentinel (KQL)", "kql", "Advanced hunting tables via pySigma Kusto backend"),
    "elastic": Target("elastic", "Elastic (Lucene, ECS)", "lucene", "Winlogbeat/ECS fields via pySigma Elasticsearch backend"),
    "wazuh": Target("wazuh", "Wazuh (XML rules)", "xml", "Rules for the Wazuh windows eventchannel decoder (Sysmon)"),
}


@dataclass
class ConvertedRule:
    title: str
    rule_id: str | None
    techniques: list[str]
    tactic_ids: list[str]
    queries: list[str] = field(default_factory=list)
    error: str | None = None

    @property
    def query(self) -> str | None:
        return "\n\n".join(self.queries) if self.queries else None


@dataclass
class ConversionResult:
    target: str
    rules: list[ConvertedRule] = field(default_factory=list)

    @property
    def errors(self) -> list[str]:
        return [f"{rule.title}: {rule.error}" for rule in self.rules if rule.error]


class SigmaConversionError(ValueError):
    pass


def _backend(target: str):
    if target == "splunk":
        return SplunkBackend(sysmon_pipeline() + splunk_windows_pipeline())
    if target == "kql":
        return KustoBackend(microsoft_xdr_pipeline())
    if target == "elastic":
        return LuceneBackend(ecs_windows())
    raise SigmaConversionError(f"Unsupported target: {target}")


def _documents(sigma_yaml: str) -> list[dict[str, Any]]:
    if len(sigma_yaml) > MAX_SIGMA_CHARS:
        raise SigmaConversionError(f"Sigma input exceeds {MAX_SIGMA_CHARS} characters")
    try:
        documents = [doc for doc in yaml.safe_load_all(sigma_yaml) if doc]
    except yaml.YAMLError as error:
        raise SigmaConversionError(f"Invalid YAML: {error}") from error
    if not documents:
        raise SigmaConversionError("No Sigma rules found")
    if not all(isinstance(doc, dict) for doc in documents):
        raise SigmaConversionError("Every YAML document must be a Sigma rule mapping")
    return documents


def _attack_tags(document: dict[str, Any]) -> tuple[list[str], list[str]]:
    from app.services.attack_knowledge import TACTIC_IDS  # local: avoid import cycle

    techniques, tactics = [], []
    for tag in document.get("tags") or []:
        value = str(tag).lower()
        if not value.startswith("attack."):
            continue
        value = value[len("attack."):]
        if re.fullmatch(r"t\d{4}([._]\d{3})?", value):
            techniques.append(value.upper().replace("_", "."))
        elif re.fullmatch(r"ta\d{4}", value):
            tactics.append(value.upper())
        elif value.replace("_", " ").replace("-", " ") in TACTIC_IDS:
            tactics.append(TACTIC_IDS[value.replace("_", " ").replace("-", " ")])
    return techniques, tactics


def convert(sigma_yaml: str, target: str) -> ConversionResult:
    """Convert every rule separately so one unsupported rule does not hide the rest."""
    if target not in TARGETS:
        raise SigmaConversionError(f"Unsupported target: {target}. Use one of: {', '.join(TARGETS)}")
    result = ConversionResult(target=target)
    for document in _documents(sigma_yaml):
        title = str(document.get("title") or "untitled rule")
        techniques, tactics = _attack_tags(document)
        converted = ConvertedRule(
            title=title,
            rule_id=str(document["id"]) if document.get("id") else None,
            techniques=techniques,
            tactic_ids=tactics,
        )
        try:
            if target == "wazuh":
                converted.queries = [WazuhConverter().convert(document)]
            else:
                # Pipelines mutate the parsed rule: build a fresh collection per conversion.
                collection = SigmaCollection.from_dicts([document])
                converted.queries = [str(q) for q in _backend(target).convert(collection)]
        except (SigmaError, SigmaConversionError, ValueError, KeyError, TypeError) as error:
            converted.error = str(error).splitlines()[0][:300] or type(error).__name__
        result.rules.append(converted)
    if target == "wazuh":
        ok = [rule for rule in result.rules if rule.queries]
        for rule, xml in zip(ok, renumber_wazuh([rule.queries[0] for rule in ok]), strict=True):
            rule.queries = [xml]
    return result


# --- Wazuh -------------------------------------------------------------------

WAZUH_FIELDS = {
    "image": "win.eventdata.image",
    "commandline": "win.eventdata.commandLine",
    "parentimage": "win.eventdata.parentImage",
    "parentcommandline": "win.eventdata.parentCommandLine",
    "originalfilename": "win.eventdata.originalFileName",
    "user": "win.eventdata.user",
    "hashes": "win.eventdata.hashes",
    "targetobject": "win.eventdata.targetObject",
    "details": "win.eventdata.details",
    "targetfilename": "win.eventdata.targetFilename",
    "destinationip": "win.eventdata.destinationIp",
    "destinationport": "win.eventdata.destinationPort",
    "destinationhostname": "win.eventdata.destinationHostname",
    "sourceip": "win.eventdata.sourceIp",
    "queryname": "win.eventdata.queryName",
    "imageloaded": "win.eventdata.imageLoaded",
    "targetimage": "win.eventdata.targetImage",
    "sourceimage": "win.eventdata.sourceImage",
}
WAZUH_EVENT_IDS = {
    "process_creation": "1",
    "network_connection": "3",
    "image_load": "7",
    "create_remote_thread": "8",
    "process_access": "10",
    "file_event": "11",
    "registry_add": "12",
    "registry_set": "13",
    "registry_event": "12|13|14",
    "dns_query": "22",
}
WAZUH_LEVELS = {"informational": 3, "low": 5, "medium": 8, "high": 12, "critical": 15}


class WazuhConverter:
    """Sigma -> Wazuh XML. One <rule> per selection; selections are ORed."""

    def __init__(self, base_rule_id: int = 100100):
        self.base_rule_id = base_rule_id

    @staticmethod
    def _value_regex(value: Any, modifiers: list[str]) -> str:
        if "re" in modifiers:
            return str(value)
        # Wazuh's eventchannel decoder keeps Windows backslashes JSON-escaped
        # ("C:\\Windows\\..."), so every literal backslash must match two.
        text = str(value).replace("\\", "\\\\")
        if "*" in text or "?" in text:
            body = "".join(".*" if c == "*" else "." if c == "?" else re.escape(c) for c in text)
            return f"^{body}$"
        escaped = re.escape(text)
        if "contains" in modifiers:
            return escaped
        if "startswith" in modifiers:
            return f"^{escaped}"
        if "endswith" in modifiers:
            return f"{escaped}$"
        return f"^{escaped}$"

    def _field(self, spec: str, value: Any) -> str:
        name, *modifiers = spec.split("|")
        unsupported = set(modifiers) - {"contains", "startswith", "endswith", "all", "re"}
        if unsupported:
            raise SigmaConversionError(f"modifier {'|'.join(sorted(unsupported))} not supported for Wazuh")
        wazuh_field = WAZUH_FIELDS.get(name.lower())
        if wazuh_field is None:
            raise SigmaConversionError(f"field {name} has no Wazuh eventchannel mapping")
        values = value if isinstance(value, list) else [value]
        if not values or any(isinstance(v, (dict, list)) or v is None for v in values):
            raise SigmaConversionError(f"unsupported value for {name}")
        patterns = [self._value_regex(v, modifiers) for v in values]
        if "all" in modifiers and len(patterns) > 1:
            pattern = "".join(f"(?=.*{p})" for p in patterns)
        else:
            pattern = patterns[0] if len(patterns) == 1 else "(?:" + "|".join(patterns) + ")"
        return f'    <field name="{wazuh_field}" type="pcre2">(?i){escape(pattern)}</field>'

    def convert(self, document: dict[str, Any]) -> str:
        detection = document.get("detection") or {}
        condition = str(detection.get("condition", "")).strip()
        selections = {k: v for k, v in detection.items() if k != "condition"}
        if condition in selections:
            names = [condition]
        elif re.fullmatch(r"(1|any) of (\w+\*|them)", condition):
            prefix = condition.split(" of ")[1]
            names = list(selections) if prefix == "them" else [n for n in selections if n.startswith(prefix[:-1])]
        elif re.fullmatch(r"\w+( or \w+)+", condition):
            names = condition.split(" or ")
        else:
            raise SigmaConversionError(f"condition '{condition}' is not supported for Wazuh (no and/not)")
        category = str((document.get("logsource") or {}).get("category") or "")
        event_id = WAZUH_EVENT_IDS.get(category)
        if event_id is None:
            raise SigmaConversionError(f"logsource category '{category}' has no Sysmon event mapping")
        level = WAZUH_LEVELS.get(str(document.get("level", "medium")).lower(), 8)
        techniques, _ = _attack_tags(document)
        title = escape(str(document.get("title") or "ThreatCanvas rule"))
        rules = []
        for offset, name in enumerate(names):
            selection = selections.get(name)
            if not isinstance(selection, dict) or not selection:
                raise SigmaConversionError(f"selection '{name}' must be a field map")
            fields = [self._field(spec, value) for spec, value in selection.items()]
            mitre = "".join(f"\n      <id>{escape(t)}</id>" for t in techniques)
            rules.append(
                f'  <rule id="{self.base_rule_id + offset}" level="{level}">\n'
                f"    <if_group>windows</if_group>\n"
                f'    <field name="win.system.channel">^Microsoft-Windows-Sysmon/Operational$</field>\n'
                f'    <field name="win.system.eventID">^(?:{event_id})$</field>\n'
                + "\n".join(fields)
                + f"\n    <description>{title}</description>"
                + (f"\n    <mitre>{mitre}\n    </mitre>" if techniques else "")
                + "\n  </rule>"
            )
        return '<group name="threatcanvas,sigma,">\n' + "\n".join(rules) + "\n</group>"


def renumber_wazuh(rules_xml: list[str], base_rule_id: int = 100100) -> list[str]:
    """Give every Wazuh rule across a conversion a unique, sequential id."""
    counter = [base_rule_id]

    def replace(_match: re.Match[str]) -> str:
        value = counter[0]
        counter[0] += 1
        return f'<rule id="{value}"'

    return [re.sub(r'<rule id="\d+"', replace, xml) for xml in rules_xml]
