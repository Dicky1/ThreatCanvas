import json
import logging
import os
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any

from app.schemas.cir import CIRSpecification

TACTIC_IDS = {
    "reconnaissance": "TA0043",
    "resource development": "TA0042",
    "initial access": "TA0001",
    "execution": "TA0002",
    "persistence": "TA0003",
    "privilege escalation": "TA0004",
    "defense evasion": "TA0005",
    # ATT&CK v18+ renamed Defense Evasion (TA0005) to Stealth and split out
    # Defense Impairment (TA0112). Both spellings must resolve.
    "stealth": "TA0005",
    "defense impairment": "TA0112",
    "credential access": "TA0006",
    "discovery": "TA0007",
    "lateral movement": "TA0008",
    "collection": "TA0009",
    "command and control": "TA0011",
    "exfiltration": "TA0010",
    "impact": "TA0040",
}

TACTIC_NAMES = {
    "TA0043": "Reconnaissance",
    "TA0042": "Resource Development",
    "TA0001": "Initial Access",
    "TA0002": "Execution",
    "TA0003": "Persistence",
    "TA0004": "Privilege Escalation",
    "TA0005": "Stealth",
    "TA0112": "Defense Impairment",
    "TA0006": "Credential Access",
    "TA0007": "Discovery",
    "TA0008": "Lateral Movement",
    "TA0009": "Collection",
    "TA0011": "Command and Control",
    "TA0010": "Exfiltration",
    "TA0040": "Impact",
}

logger = logging.getLogger(__name__)

DATA_DIR = Path(__file__).parents[1] / "data"
DEFAULT_BUNDLE_PATH = DATA_DIR / "enterprise-attack.json"
# Compact catalog generated from the official bundle by
# scripts/build_attack_catalog.py. Committed, so fresh clones get full coverage.
DEFAULT_CATALOG_PATH = DATA_DIR / "attack_catalog.json"


@dataclass(frozen=True)
class ATTACKTechnique:
    technique_id: str
    name: str
    tactics: tuple[str, ...] = ()
    data_sources: tuple[str, ...] = ()
    deprecated: bool = False
    version: str | None = None
    parent_id: str | None = None


def _tactic_key(name: str) -> str:
    return name.lower().replace("-", " ").strip()


@lru_cache(maxsize=8)
def _load_cached(kind: str, path: str, mtime: float) -> "ATTACKKnowledgeService":
    """Parse a default data file once per (path, mtime).

    The service is instantiated per request in several places; re-parsing the
    55MB STIX bundle each time would make every request slow.
    """
    service = ATTACKKnowledgeService(bundle={"type": "bundle", "spec_version": "2.1", "objects": []})
    if kind == "bundle":
        service.load_path(path)
    else:
        with Path(path).open(encoding="utf-8") as stream:
            service.load_catalog(json.load(stream))
    return service


@dataclass
class ATTACKKnowledgeService:
    techniques: dict[str, ATTACKTechnique] = field(default_factory=dict)
    version: str = "compatibility-catalog"
    tactic_names: dict[str, str] = field(default_factory=dict)

    def __init__(
        self,
        bundle: dict[str, Any] | None = None,
        bundle_path: str | os.PathLike[str] | None = None,
    ):
        self.techniques = {}
        self.version = "compatibility-catalog"
        self.tactic_names = dict(TACTIC_NAMES)
        if bundle is not None:
            self.load_bundle(bundle)
            return
        if bundle_path is None:
            bundle_path = os.getenv("ATTACK_STIX_PATH")
        if bundle_path:
            self.load_path(bundle_path)
            return

        # Default sources, best first: full local bundle -> committed compact
        # catalog -> tiny built-in list (last resort if data files are missing).
        for kind, path in (("bundle", DEFAULT_BUNDLE_PATH), ("catalog", DEFAULT_CATALOG_PATH)):
            if not path.exists():
                continue
            try:
                cached = _load_cached(kind, str(path), path.stat().st_mtime)
            except (OSError, ValueError) as error:  # corrupt/partial file: try the next source
                logger.warning("Ignoring unreadable ATT&CK data %s: %s", path, error)
                continue
            self.techniques = cached.techniques
            self.version = cached.version
            self.tactic_names = cached.tactic_names
            return
        self._load_compatibility_catalog()

    def load_path(self, bundle_path: str | os.PathLike[str]) -> None:
        with Path(bundle_path).open(encoding="utf-8") as stream:
            self.load_bundle(json.load(stream))

    def load_catalog(self, catalog: dict[str, Any]) -> None:
        """Load the compact catalog produced by scripts/build_attack_catalog.py."""
        techniques = catalog.get("techniques")
        if not isinstance(techniques, dict):
            raise ValueError("ATT&CK catalog must contain a 'techniques' object")
        self.techniques = {
            identifier.upper(): ATTACKTechnique(
                technique_id=identifier.upper(),
                name=entry.get("name", identifier),
                tactics=tuple(entry.get("tactics", [])),
                data_sources=tuple(entry.get("data_sources", [])),
                deprecated=bool(entry.get("deprecated")),
                version=entry.get("version"),
                parent_id=identifier.split(".")[0].upper() if "." in identifier else None,
            )
            for identifier, entry in techniques.items()
        }
        self.tactic_names.update(catalog.get("tactics", {}))
        self.version = str(catalog.get("attack_version") or "attack-catalog")

    def load_bundle(self, bundle: dict[str, Any]) -> None:
        if bundle.get("type") != "bundle":
            raise ValueError("ATT&CK input must be a STIX 2.x bundle")
        spec_version = str(bundle.get("spec_version", "2.0"))
        if not spec_version.startswith("2."):
            raise ValueError("ATT&CK input must use STIX 2.x")

        # Tactic shortname -> TA id. Prefer the bundle's own x-mitre-tactic
        # objects so renamed/new tactics (e.g. "stealth", "defense-impairment")
        # are never silently dropped.
        tactic_ids = dict(TACTIC_IDS)
        collection_version = None
        for obj in bundle.get("objects", []):
            if obj.get("type") == "x-mitre-collection" and obj.get("x_mitre_version"):
                collection_version = obj["x_mitre_version"]
            if obj.get("type") != "x-mitre-tactic" or obj.get("revoked") or obj.get("x_mitre_deprecated"):
                continue
            for reference in obj.get("external_references", []):
                identifier = reference.get("external_id", "")
                if reference.get("source_name") == "mitre-attack" and identifier.startswith("TA"):
                    tactic_ids[_tactic_key(obj.get("x_mitre_shortname", ""))] = identifier
                    if obj.get("name"):
                        self.tactic_names[identifier] = obj["name"]

        self.techniques = {}
        for obj in bundle.get("objects", []):
            if obj.get("type") != "attack-pattern":
                continue
            technique_id = self._external_id(obj)
            if not technique_id:
                continue
            phases = tuple(
                tactic_ids[_tactic_key(phase["phase_name"])]
                for phase in obj.get("kill_chain_phases", [])
                if phase.get("kill_chain_name") == "mitre-attack"
                and _tactic_key(phase.get("phase_name", "")) in tactic_ids
            )
            deprecated = bool(obj.get("revoked") or obj.get("x_mitre_deprecated"))
            existing = self.techniques.get(technique_id)
            if existing and not existing.deprecated and deprecated:
                continue
            self.techniques[technique_id] = ATTACKTechnique(
                technique_id=technique_id,
                name=obj.get("name", technique_id),
                tactics=phases,
                data_sources=tuple(obj.get("x_mitre_data_sources", [])),
                deprecated=deprecated,
                version=obj.get("x_mitre_version"),
                parent_id=obj.get("x_mitre_parent_attack_id"),
            )
            if obj.get("x_mitre_version"):
                self.version = obj["x_mitre_version"]
        if collection_version:
            self.version = collection_version

    def resolve_technique(self, technique_id: str) -> ATTACKTechnique | None:
        return self.techniques.get(technique_id.strip().upper())

    def resolve_technique_name(self, technique_id: str) -> str | None:
        technique = self.resolve_technique(technique_id)
        return technique.name if technique else None

    def resolve_subtechniques(self, technique_id: str) -> list[ATTACKTechnique]:
        prefix = f"{technique_id.strip().upper()}."
        return [
            technique
            for identifier, technique in self.techniques.items()
            if identifier.startswith(prefix)
        ]

    def validate_node(self, technique_id: str, tactic_id: str) -> list[str]:
        technique = self.resolve_technique(technique_id)
        if technique is None:
            return [f"Unknown ATT&CK technique: {technique_id}"]
        if technique.deprecated:
            return [f"Deprecated ATT&CK technique: {technique_id}"]
        if tactic_id.strip().upper() not in technique.tactics:
            return [
                f"Tactic {tactic_id} is not mapped to ATT&CK technique {technique_id}"
            ]
        return []

    def resolve_cir(self, cir: CIRSpecification) -> CIRSpecification:
        resolved = cir.model_copy(deep=True)
        resolved.attack_version = self.version
        for node in resolved.attack_graph.nodes:
            technique = self.resolve_technique(node.technique)
            if technique is None:
                continue
            node.technique = technique.technique_id
            node.technique_name = technique.name
            node.tactic_name = self.tactic_names.get(node.tactic)
            node.attack_version = technique.version or self.version
            node.attack_data_sources = list(technique.data_sources)
            node.technique_deprecated = technique.deprecated
        return resolved

    def _external_id(self, obj: dict[str, Any]) -> str | None:
        for reference in obj.get("external_references", []):
            identifier = reference.get("external_id", "")
            if reference.get("source_name") in {"mitre-attack", "mitre-mobile-attack", "mitre-ics-attack"} and identifier.startswith("T"):
                return identifier.upper()
        return None

    def _load_compatibility_catalog(self) -> None:
        # Last-resort list used only if app/data/attack_catalog.json is missing.
        # Tactic mappings follow the official ATT&CK release (v20).
        entries = {
            "T1003": ("OS Credential Dumping", ("TA0006",)),
            "T1003.001": ("LSASS Memory", ("TA0006",)),
            "T1016": ("System Network Configuration Discovery", ("TA0007",)),
            "T1021": ("Remote Services", ("TA0008",)),
            "T1021.001": ("Remote Desktop Protocol", ("TA0008",)),
            "T1021.002": ("SMB/Windows Admin Shares", ("TA0008",)),
            "T1027": ("Obfuscated Files or Information", ("TA0005",)),
            "T1036": ("Masquerading", ("TA0005",)),
            "T1041": ("Exfiltration Over C2 Channel", ("TA0010",)),
            "T1047": ("Windows Management Instrumentation", ("TA0002",)),
            "T1048": ("Exfiltration Over Alternative Protocol", ("TA0010",)),
            "T1049": ("System Network Connections Discovery", ("TA0007",)),
            "T1053": ("Scheduled Task/Job", ("TA0002", "TA0003", "TA0004",)),
            "T1053.005": ("Scheduled Task", ("TA0002", "TA0003", "TA0004",)),
            "T1055": ("Process Injection", ("TA0005", "TA0004",)),
            "T1057": ("Process Discovery", ("TA0007",)),
            "T1059": ("Command and Scripting Interpreter", ("TA0002",)),
            "T1059.001": ("PowerShell", ("TA0002",)),
            "T1070.004": ("File Deletion", ("TA0005",)),
            "T1071.001": ("Web Protocols", ("TA0011",)),
            "T1071.004": ("DNS", ("TA0011",)),
            "T1078": ("Valid Accounts", ("TA0005", "TA0003", "TA0004", "TA0001",)),
            "T1082": ("System Information Discovery", ("TA0007",)),
            "T1083": ("File and Directory Discovery", ("TA0007",)),
            "T1087": ("Account Discovery", ("TA0007",)),
            "T1105": ("Ingress Tool Transfer", ("TA0011",)),
            "T1112": ("Modify Registry", ("TA0112", "TA0003",)),
            "T1190": ("Exploit Public-Facing Application", ("TA0001",)),
            "T1204": ("User Execution", ("TA0002",)),
            "T1204.002": ("Malicious File", ("TA0002",)),
            "T1218": ("System Binary Proxy Execution", ("TA0005",)),
            "T1486": ("Data Encrypted for Impact", ("TA0040",)),
            "T1489": ("Service Stop", ("TA0040",)),
            "T1490": ("Inhibit System Recovery", ("TA0040",)),
            "T1505.003": ("Web Shell", ("TA0003",)),
            "T1531": ("Account Access Removal", ("TA0040",)),
            "T1547": ("Boot or Logon Autostart Execution", ("TA0003", "TA0004",)),
            "T1547.001": ("Registry Run Keys / Startup Folder", ("TA0003", "TA0004",)),
            "T1550.002": ("Pass the Hash", ("TA0008",)),
            "T1555": ("Credentials from Password Stores", ("TA0006",)),
            "T1557": ("Adversary-in-the-Middle", ("TA0006", "TA0009",)),
            "T1557.001": ("Name Resolution Poisoning and SMB Relay", ("TA0006", "TA0009",)),
            "T1557.002": ("ARP Cache Poisoning", ("TA0006", "TA0009",)),
            "T1558.003": ("Kerberoasting", ("TA0006",)),
            "T1560": ("Archive Collected Data", ("TA0009",)),
            "T1562": ("Impair Defenses", ("TA0005",)),
            "T1562.001": ("Disable or Modify Tools", ("TA0005",)),
            "T1566": ("Phishing", ("TA0001",)),
            "T1566.001": ("Spearphishing Attachment", ("TA0001",)),
            "T1567": ("Exfiltration Over Web Service", ("TA0010",)),
            "T1570": ("Lateral Tool Transfer", ("TA0008",)),
            "T1574.002": ("DLL Side-Loading", ("TA0005", "TA0002",)),
            "T1587.001": ("Malware", ("TA0042",)),
            "T1588.002": ("Tool", ("TA0042",)),
            "T1588.006": ("Vulnerabilities", ("TA0042",)),
            "T1608.001": ("Upload Malware", ("TA0042",)),
        }
        self.techniques = {
            identifier: ATTACKTechnique(identifier, name, tactics)
            for identifier, (name, tactics) in entries.items()
        }
