"""Evaluates Sigma rules against log events (dicts), so generated rules can
be measured on real datasets (OTRF Security-Datasets, Atomic Red Team EVTX).

pySigma converts rules to SIEM queries but cannot execute them; this module
implements the Sigma matching semantics needed for that:

- detection identifiers: map (fields ANDed), list of maps (ORed), list of
  keywords (matched against any value)
- value modifiers: contains, startswith, endswith, all, re, cidr, exists,
  windash; wildcards ``*`` / ``?`` in plain values; ``null`` values
- conditions: and / or / not, parentheses, ``1 of x*``, ``all of x*``,
  ``1 of them``, ``all of them``
- logsource filtering for Sysmon / Windows Security channels

String comparisons are case-insensitive, as in Sigma.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from functools import lru_cache
from typing import Any

import regex
import yaml


class SigmaEvalError(ValueError):
    """The rule uses syntax this evaluator does not support."""


# Rules may come from users: every pattern match runs with a timeout so a
# catastrophic-backtracking regex or wildcard cannot stall the server.
MATCH_TIMEOUT_SECONDS = 0.25
MAX_VALUE_CHARS = 32_768


SUPPORTED_MODIFIERS = {"contains", "startswith", "endswith", "all", "re", "cidr", "exists", "windash", "i", "m", "s"}

# logsource category -> accepted (channel, event ids). Events without channel/
# event id information are not filtered (generic JSON logs).
SYSMON = "microsoft-windows-sysmon/operational"
SECURITY = "security"
LOGSOURCE_EVENTS: dict[str, list[tuple[str, set[int]]]] = {
    "process_creation": [(SYSMON, {1}), (SECURITY, {4688})],
    "network_connection": [(SYSMON, {3})],
    "file_event": [(SYSMON, {11})],
    "file_delete": [(SYSMON, {23, 26})],
    "registry_set": [(SYSMON, {13})],
    "registry_add": [(SYSMON, {12})],
    "registry_delete": [(SYSMON, {12})],
    "registry_event": [(SYSMON, {12, 13, 14})],
    "image_load": [(SYSMON, {7})],
    "dns_query": [(SYSMON, {22})],
    "process_access": [(SYSMON, {10})],
    "create_remote_thread": [(SYSMON, {8})],
    "pipe_created": [(SYSMON, {17, 18})],
    "wmi_event": [(SYSMON, {19, 20, 21})],
    "ps_script": [("microsoft-windows-powershell/operational", {4104})],
}

# Windows Security 4688 uses different names for the Sysmon-style fields.
FIELD_ALIASES = {
    "image": ("Image", "NewProcessName"),
    "parentimage": ("ParentImage", "ParentProcessName"),
    "commandline": ("CommandLine", "ProcessCommandLine"),
}


@dataclass
class CompiledRule:
    title: str
    rule_id: str | None
    tags: list[str]
    logsource: dict[str, Any]
    detection: dict[str, Any]
    condition: str
    _ast: Any = field(default=None, repr=False)

    @property
    def techniques(self) -> list[str]:
        return [
            tag.split(".", 1)[1].upper()
            for tag in self.tags
            if re.fullmatch(r"attack\.t\d{4}(\.\d{3})?", str(tag).lower())
        ]


# --- condition parsing -------------------------------------------------------

_TOKEN_RE = re.compile(r"\s*(\(|\)|[^\s()]+)")


def _tokenize(condition: str) -> list[str]:
    tokens = _TOKEN_RE.findall(condition)
    if "".join(tokens).replace(" ", "") != condition.replace(" ", ""):
        raise SigmaEvalError(f"Unsupported condition syntax: {condition!r}")
    return tokens


class _Parser:
    """Recursive descent: or_expr := and_expr ('or' and_expr)*, etc."""

    def __init__(self, tokens: list[str]):
        self.tokens = tokens
        self.pos = 0

    def peek(self) -> str | None:
        return self.tokens[self.pos] if self.pos < len(self.tokens) else None

    def take(self) -> str:
        token = self.peek()
        if token is None:
            raise SigmaEvalError("Unexpected end of condition")
        self.pos += 1
        return token

    def parse(self):
        node = self.or_expr()
        if self.peek() is not None:
            raise SigmaEvalError(f"Unexpected token {self.peek()!r} in condition")
        return node

    def or_expr(self):
        node = self.and_expr()
        while (self.peek() or "").lower() == "or":
            self.take()
            node = ("or", node, self.and_expr())
        return node

    def and_expr(self):
        node = self.not_expr()
        while (self.peek() or "").lower() == "and":
            self.take()
            node = ("and", node, self.not_expr())
        return node

    def not_expr(self):
        if (self.peek() or "").lower() == "not":
            self.take()
            return ("not", self.not_expr())
        return self.atom()

    def atom(self):
        token = self.take()
        lowered = token.lower()
        if token == "(":
            node = self.or_expr()
            if self.take() != ")":
                raise SigmaEvalError("Unbalanced parentheses in condition")
            return node
        if lowered in {"1", "all", "any"} and (self.peek() or "").lower() == "of":
            self.take()
            target = self.take()
            return ("of", "all" if lowered == "all" else "any", target)
        if lowered in {"and", "or", "not", ")", "|"} or "|" in token:
            raise SigmaEvalError(f"Unsupported condition token {token!r}")
        return ("id", token)


# --- value matching ------------------------------------------------------------

def _wildcard_regex(value: str) -> regex.Pattern:
    parts = []
    i = 0
    while i < len(value):
        char = value[i]
        if char == "\\" and i + 1 < len(value) and value[i + 1] in "*?\\":
            parts.append(re.escape(value[i + 1]))
            i += 2
            continue
        parts.append(".*" if char == "*" else "." if char == "?" else re.escape(char))
        i += 1
    return regex.compile("^" + "".join(parts) + "$", regex.IGNORECASE | regex.DOTALL)


_UNESCAPE_RE = re.compile(r"\\([\\*?])")


@lru_cache(maxsize=4096)
def _compiled_wildcard(value: str) -> regex.Pattern:
    if len(value) > 2000:
        raise SigmaEvalError("Match value too long")
    return _wildcard_regex(value)


@lru_cache(maxsize=1024)
def _compiled_regex(pattern: str, flags: int) -> regex.Pattern:
    if len(pattern) > 1000:
        raise SigmaEvalError("Regular expression too long")
    try:
        return regex.compile(pattern, flags)
    except regex.error as error:
        raise SigmaEvalError(f"Invalid regular expression {pattern!r}: {error}") from error


def _search(pattern: regex.Pattern, text: str, anchored: bool) -> bool:
    try:
        method = pattern.match if anchored else pattern.search
        return method(text[:MAX_VALUE_CHARS], timeout=MATCH_TIMEOUT_SECONDS) is not None
    except TimeoutError as error:
        raise SigmaEvalError("Pattern matching timed out (pattern too expensive)") from error


def _windash_variants(value: str) -> list[str]:
    variants = {value}
    for match in re.finditer(r"(?<!\S)[-/]", value):
        for dash in ("-", "/", "–", "—", "―"):
            variants.add(value[: match.start()] + dash + value[match.end():])
    return list(variants)


def _match_one(actual: Any, expected: Any, modifiers: list[str]) -> bool:
    if expected is None:
        return actual is None or actual == ""
    if actual is None:
        return False
    actual_text = str(actual)
    if "re" in modifiers:
        flags = regex.IGNORECASE if "i" in modifiers else 0
        flags |= regex.MULTILINE if "m" in modifiers else 0
        flags |= regex.DOTALL if "s" in modifiers else 0
        return _search(_compiled_regex(str(expected), flags), actual_text, anchored=False)
    if "cidr" in modifiers:
        try:
            return ipaddress.ip_address(actual_text.strip()) in ipaddress.ip_network(str(expected), strict=False)
        except ValueError:
            return False
    if isinstance(expected, (int, float)) and not isinstance(expected, bool):
        try:
            return float(actual_text) == float(expected)
        except ValueError:
            return False
    expected_text = str(expected)
    candidates = _windash_variants(expected_text) if "windash" in modifiers else [expected_text]
    lowered = actual_text.lower()
    for candidate in candidates:
        if "*" not in candidate and "?" not in candidate:
            # Fast path without regex for plain values (the common case).
            # Sigma escaping: "\\" is one literal backslash (as in the regex path).
            needle = _UNESCAPE_RE.sub(r"\1", candidate).lower()
            if "contains" in modifiers:
                hit = needle in lowered
            elif "startswith" in modifiers:
                hit = lowered.startswith(needle)
            elif "endswith" in modifiers:
                hit = lowered.endswith(needle)
            else:
                hit = lowered == needle
            if hit:
                return True
            continue
        if "contains" in modifiers:
            pattern = "*" + candidate + "*"
        elif "startswith" in modifiers:
            pattern = candidate + "*"
        elif "endswith" in modifiers:
            pattern = "*" + candidate
        else:
            pattern = candidate
        if _search(_compiled_wildcard(pattern), actual_text, anchored=True):
            return True
    return False


def _event_value(event: dict[str, Any], field_name: str) -> tuple[bool, Any]:
    lowered = field_name.lower()
    names = FIELD_ALIASES.get(lowered, (field_name,))
    lookup = event.get("__lower__")
    if lookup is None:
        lookup = {key.lower(): value for key, value in event.items()}
    for name in names:
        if name.lower() in lookup:
            return True, lookup[name.lower()]
    return False, None


def _match_field(event: dict[str, Any], spec: str, expected: Any) -> bool:
    field_name, *modifiers = spec.split("|")
    unknown = set(modifiers) - SUPPORTED_MODIFIERS
    if unknown:
        raise SigmaEvalError(f"Unsupported Sigma modifier(s): {', '.join(sorted(unknown))}")
    present, actual = _event_value(event, field_name)
    if "exists" in modifiers:
        return present == bool(expected)
    values = expected if isinstance(expected, list) else [expected]
    if not values:
        return False
    results = (_match_one(actual, value, modifiers) for value in values)
    return all(results) if "all" in modifiers else any(results)


def _match_keywords(event: dict[str, Any], keywords: Iterable[Any]) -> bool:
    texts = [str(value) for key, value in event.items() if key != "__lower__" and value is not None]
    return any(
        _search(_compiled_wildcard(f"*{keyword}*"), text, anchored=True)
        for keyword in keywords
        for text in texts
    )


def _match_identifier(event: dict[str, Any], definition: Any) -> bool:
    if isinstance(definition, dict):
        return all(_match_field(event, spec, value) for spec, value in definition.items())
    if isinstance(definition, list):
        if all(isinstance(item, dict) for item in definition):
            return any(_match_identifier(event, item) for item in definition)
        if all(not isinstance(item, (dict, list)) for item in definition):
            return _match_keywords(event, definition)
    if isinstance(definition, (str, int)):
        return _match_keywords(event, [definition])
    raise SigmaEvalError("Unsupported detection identifier structure")


# --- rules -------------------------------------------------------------------

def compile_rules(sigma_yaml: str) -> tuple[list[CompiledRule], list[str]]:
    """Parse (possibly multi-document) Sigma YAML. Returns rules + errors."""
    rules: list[CompiledRule] = []
    errors: list[str] = []
    try:
        documents = [doc for doc in yaml.safe_load_all(sigma_yaml) if doc]
    except yaml.YAMLError as error:
        return [], [f"Invalid YAML: {error}"]
    for index, document in enumerate(documents, start=1):
        if not isinstance(document, dict) or "detection" not in document:
            errors.append(f"Document {index}: not a Sigma rule")
            continue
        title = str(document.get("title") or f"rule {index}")
        detection = document.get("detection")
        if not isinstance(detection, dict) or "condition" not in detection:
            errors.append(f"{title}: detection must contain a condition")
            continue
        condition = detection["condition"]
        if isinstance(condition, list):
            if len(condition) != 1:
                errors.append(f"{title}: multiple conditions are not supported")
                continue
            condition = condition[0]
        if " | " in str(condition):
            errors.append(f"{title}: aggregation conditions are not supported")
            continue
        try:
            ast = _Parser(_tokenize(str(condition))).parse()
            identifiers = {k: v for k, v in detection.items() if k != "condition"}
            _check_identifiers(ast, identifiers)
        except SigmaEvalError as error:
            errors.append(f"{title}: {error}")
            continue
        rules.append(CompiledRule(
            title=title,
            rule_id=str(document.get("id")) if document.get("id") else None,
            tags=[str(tag) for tag in document.get("tags") or []],
            logsource=document.get("logsource") or {},
            detection=identifiers,
            condition=str(condition),
            _ast=ast,
        ))
    return rules, errors


def _matching_identifiers(pattern: str, identifiers: dict[str, Any]) -> list[str]:
    if pattern == "them":
        return [name for name in identifiers if not name.startswith("_")]
    matcher = _compiled_wildcard(pattern)
    return [name for name in identifiers if _search(matcher, name, anchored=True)]


def _check_identifiers(node, identifiers: dict[str, Any]) -> None:
    kind = node[0]
    if kind == "id":
        if node[1] not in identifiers:
            raise SigmaEvalError(f"Condition references unknown identifier {node[1]!r}")
    elif kind == "of":
        if not _matching_identifiers(node[2], identifiers):
            raise SigmaEvalError(f"Condition '{node[1]} of {node[2]}' matches no identifier")
    elif kind == "not":
        _check_identifiers(node[1], identifiers)
    else:
        _check_identifiers(node[1], identifiers)
        _check_identifiers(node[2], identifiers)


def _evaluate(node, event: dict[str, Any], identifiers: dict[str, Any]) -> bool:
    kind = node[0]
    if kind == "id":
        return _match_identifier(event, identifiers[node[1]])
    if kind == "not":
        return not _evaluate(node[1], event, identifiers)
    if kind == "and":
        return _evaluate(node[1], event, identifiers) and _evaluate(node[2], event, identifiers)
    if kind == "or":
        return _evaluate(node[1], event, identifiers) or _evaluate(node[2], event, identifiers)
    names = _matching_identifiers(node[2], identifiers)
    results = (_match_identifier(event, identifiers[name]) for name in names)
    return all(results) if node[1] == "all" else any(results)


def logsource_applies(rule: CompiledRule, event: dict[str, Any]) -> bool:
    category = str(rule.logsource.get("category") or "").lower()
    accepted = LOGSOURCE_EVENTS.get(category)
    if not accepted:
        return True
    _, channel = _event_value(event, "Channel")
    _, event_id = _event_value(event, "EventID")
    if channel is None and event_id is None:
        return True  # generic logs without Windows metadata
    try:
        event_id = int(event_id) if event_id is not None else None
    except (TypeError, ValueError):
        event_id = None
    channel_text = str(channel or "").lower()
    for accepted_channel, accepted_ids in accepted:
        if (not channel_text or channel_text == accepted_channel) and (event_id is None or event_id in accepted_ids):
            return True
    return False


def rule_matches(rule: CompiledRule, event: dict[str, Any]) -> bool:
    if not logsource_applies(rule, event):
        return False
    return _evaluate(rule._ast, event, rule.detection)


def prepare_event(event: dict[str, Any]) -> dict[str, Any]:
    """Adds a lower-cased key index used for case-insensitive field lookup."""
    prepared = dict(event)
    prepared["__lower__"] = {key.lower(): value for key, value in event.items()}
    return prepared
