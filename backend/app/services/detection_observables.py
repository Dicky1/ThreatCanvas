"""Turns CIR evidence into detection observables shared by the Sigma, KQL and
SPL compilers, so all three describe the same telemetry.

Observables use Sigma/Sysmon field names (Image, CommandLine, TargetObject,
DestinationIp, ...). Structured evidence fields are used first; when an
evidence item only has free text (typical for LLM output) a small set of
conservative patterns extracts file names, LOLBins, registry keys, IPs,
domains and well-known malicious command fragments from it.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import urlparse

from app.schemas.cir import CIRNode, Evidence

PROCESS = "process_creation"
REGISTRY = "registry_set"
FILE = "file_event"
NETWORK = "network_connection"

CATEGORY_ORDER = (PROCESS, REGISTRY, FILE, NETWORK)


@dataclass(frozen=True)
class Observable:
    category: str
    field: str
    op: str  # "endswith" | "contains" | "equals"
    value: str
    inferred: bool = False


@dataclass
class ObservableGroup:
    """Observables from one evidence item and one telemetry category (ANDed)."""

    category: str
    observables: list[Observable]

    @property
    def inferred(self) -> bool:
        return all(observable.inferred for observable in self.observables)


LOLBINS = (
    "powershell", "pwsh", "cmd", "rundll32", "regsvr32", "mshta", "wscript",
    "cscript", "schtasks", "wmic", "psexec", "vssadmin", "certutil",
    "bitsadmin", "bcdedit", "wevtutil", "mimikatz", "procdump", "msiexec",
    "installutil", "regasm", "regsvcs", "msbuild", "nltest", "adfind",
)
EXEC_EXT = ("exe",)
SCRIPT_EXT = ("ps1", "bat", "cmd", "vbs", "js", "hta", "jse", "vbe", "wsf")
FILE_EXT = ("dll", "docm", "xlsm", "doc", "xls", "zip", "iso", "img", "lnk", "rar", "7z", "scr", "one")

_FILENAME_RE = re.compile(
    r"(?<![\w.-])([\w-]+\.(?:" + "|".join(EXEC_EXT + SCRIPT_EXT + FILE_EXT) + r"))\b",
    re.IGNORECASE,
)
_LOLBIN_RE = re.compile(r"\b(" + "|".join(LOLBINS) + r")\b(?!\.)", re.IGNORECASE)
_REGISTRY_RE = re.compile(
    r"\b(?:HKLM|HKCU|HKCR|HKU|HKCC|HKEY_[A-Z_]+)\\([^\s,;\"'`)]+)", re.IGNORECASE
)
_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_DOMAIN_RE = re.compile(
    r"\b((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"(?:com|net|org|io|ru|cn|xyz|top|info|biz|co|me|cc|tk|su|pw|onion|online|site))\b",
    re.IGNORECASE,
)
_COMMAND_RE = re.compile(
    r"(Invoke-[A-Za-z]+|\bIEX\b|DownloadString|DownloadFile|EncodedCommand|"
    r"FromBase64String|sekurlsa::\w+|lsadump::\w+|delete shadows|shadowcopy delete|"
    r"recoveryenabled\s+no|wevtutil\s+cl|-ExecutionPolicy\s+Bypass)",
    re.IGNORECASE,
)
# Backticks / double quotes only: apostrophes in prose ("user's") are not quotes.
_QUOTED_RE = re.compile(r"[`\"]([^`\"]{6,200})[`\"]")


def _add(bucket: dict[str, list[Observable]], observable: Observable) -> None:
    items = bucket.setdefault(observable.category, [])
    if all((o.field, o.value.lower()) != (observable.field, observable.value.lower()) for o in items):
        items.append(observable)


def _basename(path: str) -> str:
    return re.split(r"[\\/]", path.strip())[-1]


def _structured(evidence: Evidence, bucket: dict[str, list[Observable]]) -> None:
    if evidence.image:
        _add(bucket, Observable(PROCESS, "Image", "endswith", "\\" + _basename(evidence.image)))
    if evidence.command_line:
        _add(bucket, Observable(PROCESS, "CommandLine", "contains", evidence.command_line.strip()))
    if evidence.hash_sha256:
        _add(bucket, Observable(PROCESS, "Hashes", "contains", f"SHA256={evidence.hash_sha256.strip().upper()}"))
    if evidence.registry_key:
        key = _REGISTRY_RE.search(evidence.registry_key)
        _add(bucket, Observable(REGISTRY, "TargetObject", "contains", "\\" + (key.group(1) if key else evidence.registry_key.strip())))
    if evidence.registry_value:
        _add(bucket, Observable(REGISTRY, "Details", "contains", evidence.registry_value.strip()))
    if evidence.filename:
        _add(bucket, Observable(FILE, "TargetFilename", "endswith", "\\" + _basename(evidence.filename)))
    if evidence.ip:
        _add(bucket, Observable(NETWORK, "DestinationIp", "equals", evidence.ip.strip()))
    if evidence.domain:
        _add(bucket, Observable(NETWORK, "DestinationHostname", "contains", evidence.domain.strip().lower()))
    if evidence.url:
        host = urlparse(evidence.url if "://" in evidence.url else f"http://{evidence.url}").hostname
        if host:
            _add(bucket, Observable(NETWORK, "DestinationHostname", "contains", host.lower()))


def _from_text(text: str, bucket: dict[str, list[Observable]]) -> None:
    for match in _REGISTRY_RE.finditer(text):
        _add(bucket, Observable(REGISTRY, "TargetObject", "contains", "\\" + match.group(1), True))
    filenames = {m.group(1) for m in _FILENAME_RE.finditer(text)}
    for name in sorted(filenames):
        ext = name.rsplit(".", 1)[-1].lower()
        if ext in EXEC_EXT:
            _add(bucket, Observable(PROCESS, "Image", "endswith", "\\" + name, True))
        elif ext in SCRIPT_EXT:
            _add(bucket, Observable(PROCESS, "CommandLine", "contains", name, True))
        else:
            _add(bucket, Observable(FILE, "TargetFilename", "endswith", "\\" + name, True))
    lowered_files = {name.lower().rsplit(".", 1)[0] for name in filenames}
    for match in _LOLBIN_RE.finditer(text):
        tool = match.group(1).lower()
        if tool not in lowered_files:
            _add(bucket, Observable(PROCESS, "Image", "endswith", f"\\{tool}.exe", True))
    for match in _COMMAND_RE.finditer(text):
        _add(bucket, Observable(PROCESS, "CommandLine", "contains", match.group(1), True))
    for match in _QUOTED_RE.finditer(text):
        fragment = match.group(1).strip()
        if " " in fragment or "-" in fragment:
            _add(bucket, Observable(PROCESS, "CommandLine", "contains", fragment, True))
    for match in _IPV4_RE.finditer(text):
        try:
            if ipaddress.ip_address(match.group(0)).is_global:
                _add(bucket, Observable(NETWORK, "DestinationIp", "equals", match.group(0), True))
        except ValueError:
            continue
    for match in _DOMAIN_RE.finditer(text):
        domain = match.group(1).lower()
        if domain.rsplit(".", 1)[0] not in lowered_files:
            _add(bucket, Observable(NETWORK, "DestinationHostname", "contains", domain, True))


def node_observable_groups(node: CIRNode) -> list[ObservableGroup]:
    """One group per (evidence item, telemetry category).

    Inside a group observables are ANDed (they describe the same event);
    groups are ORed (each evidence item is an independent indicator).
    """
    groups: list[ObservableGroup] = []
    seen: set[tuple] = set()
    for evidence in node.evidence:
        bucket: dict[str, list[Observable]] = {}
        _structured(evidence, bucket)
        if not bucket:
            text = " ".join(filter(None, [evidence.command_line, evidence.evidence_text, evidence.description]))
            _from_text(text, bucket)
            # Free text yields independent hints, not one event: OR them.
            for category in CATEGORY_ORDER:
                for observable in bucket.get(category, []):
                    key = (category, ((observable.field, observable.value.lower()),))
                    if key not in seen:
                        seen.add(key)
                        groups.append(ObservableGroup(category, [observable]))
            continue
        for category in CATEGORY_ORDER:
            observables = bucket.get(category)
            if not observables:
                continue
            key = (category, tuple(sorted((o.field, o.value.lower()) for o in observables)))
            if key not in seen:
                seen.add(key)
                groups.append(ObservableGroup(category, observables))
    return groups
