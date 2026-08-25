import json
import os
from dataclasses import dataclass, field
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
    "credential access": "TA0006",
    "discovery": "TA0007",
    "lateral movement": "TA0008",
    "collection": "TA0009",
    "command and control": "TA0011",
    "exfiltration": "TA0010",
    "impact": "TA0040",
}


@dataclass(frozen=True)
class ATTACKTechnique:
    technique_id: str
    name: str
    tactics: tuple[str, ...] = ()
    data_sources: tuple[str, ...] = ()
    deprecated: bool = False
    version: str | None = None
    parent_id: str | None = None


@dataclass
class ATTACKKnowledgeService:
    techniques: dict[str, ATTACKTechnique] = field(default_factory=dict)
    version: str = "compatibility-catalog"

    def __init__(
        self,
        bundle: dict[str, Any] | None = None,
        bundle_path: str | os.PathLike[str] | None = None,
    ):
        self.techniques = {}
        self.version = "compatibility-catalog"
        if bundle_path is None:
            bundle_path = os.getenv("ATTACK_STIX_PATH")
        if bundle_path:
            self.load_path(bundle_path)
        elif bundle is not None:
            self.load_bundle(bundle)
        else:
            self._load_compatibility_catalog()

    def load_path(self, bundle_path: str | os.PathLike[str]) -> None:
        with Path(bundle_path).open(encoding="utf-8") as stream:
            self.load_bundle(json.load(stream))

    def load_bundle(self, bundle: dict[str, Any]) -> None:
        if bundle.get("type") != "bundle":
            raise ValueError("ATT&CK input must be a STIX 2.x bundle")
        spec_version = str(bundle.get("spec_version", "2.0"))
        if not spec_version.startswith("2."):
            raise ValueError("ATT&CK input must use STIX 2.x")

        self.techniques = {}
        for obj in bundle.get("objects", []):
            if obj.get("type") != "attack-pattern":
                continue
            technique_id = self._external_id(obj)
            if not technique_id:
                continue
            phases = tuple(
                TACTIC_IDS[phase["phase_name"].lower()]
                for phase in obj.get("kill_chain_phases", [])
                if phase.get("kill_chain_name") == "mitre-attack"
                and phase.get("phase_name", "").lower() in TACTIC_IDS
            )
            self.techniques[technique_id] = ATTACKTechnique(
                technique_id=technique_id,
                name=obj.get("name", technique_id),
                tactics=phases,
                data_sources=tuple(obj.get("x_mitre_data_sources", [])),
                deprecated=bool(obj.get("revoked") or obj.get("x_mitre_deprecated")),
                version=obj.get("x_mitre_version"),
                parent_id=obj.get("x_mitre_parent_attack_id"),
            )
            if obj.get("x_mitre_version"):
                self.version = obj["x_mitre_version"]

    def resolve_technique(self, technique_id: str) -> ATTACKTechnique | None:
        return self.techniques.get(technique_id.strip().upper())

    def resolve_technique_name(self, technique_id: str) -> str | None:
        technique = self.resolve_technique(technique_id)
        return technique.name if technique else None

    def resolve_tactics(self, technique_id: str) -> tuple[str, ...]:
        technique = self.resolve_technique(technique_id)
        return technique.tactics if technique else ()

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
            node.tactic_name = next(
                (name for name, identifier in TACTIC_IDS.items() if identifier == node.tactic),
                None,
            )
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
        entries = {
            "T1566": ("Phishing", ("TA0001",)),
            "T1566.001": ("Spearphishing Attachment", ("TA0001",)),
            "T1190": ("Exploit Public-Facing Application", ("TA0001",)),
            "T1588.002": ("Obtain Capabilities: Tool", ("TA0042",)),
            "T1588.006": ("Obtain Capabilities: Vulnerabilities", ("TA0042",)),
            "T1587.001": ("Develop Capabilities: Malware", ("TA0042",)),
            "T1608.001": ("Stage Capabilities: Upload Malware", ("TA0042",)),
            "T1204": ("User Execution", ("TA0001",)),
            "T1204.002": ("Malicious File", ("TA0001",)),
            "T1059.001": ("PowerShell", ("TA0002",)),
            "T1059": ("Command and Scripting Interpreter", ("TA0002",)),
            "T1105": ("Ingress Tool Transfer", ("TA0011",)),
            "T1562.001": ("Impair Defenses", ("TA0005",)),
            "T1112": ("Modify Registry", ("TA0005",)),
            "T1003": ("OS Credential Dumping", ("TA0006",)),
            "T1003.001": ("LSASS Memory", ("TA0006",)),
            "T1555": ("Credentials from Password Stores", ("TA0006",)),
            "T1558.003": ("Kerberoasting", ("TA0006",)),
            "T1053": ("Scheduled Task/Job", ("TA0003",)),
            "T1053.005": ("Scheduled Task", ("TA0003",)),
            "T1547.001": ("Registry Run Keys / Startup Folder", ("TA0003",)),
            "T1016": ("System Network Configuration Discovery", ("TA0007",)),
            "T1087": ("Account Discovery", ("TA0007",)),
            "T1049": ("System Network Connections Discovery", ("TA0007",)),
            "T1021": ("Remote Services", ("TA0008",)),
            "T1021.001": ("Remote Desktop Protocol", ("TA0008",)),
            "T1021.002": ("SMB / Windows Admin Shares", ("TA0008",)),
            "T1078": ("Valid Accounts", ("TA0008", "TA0003", "TA0004", "TA0005")),
            "T1574.002": ("DLL Side-Loading", ("TA0004", "TA0005")),
            "T1041": ("Exfiltration Over C2 Channel", ("TA0010",)),
            "T1048": ("Exfiltration Over Alternative Protocol", ("TA0010",)),
            "T1486": ("Data Encrypted for Impact", ("TA0040",)),
            "T1490": ("Inhibit System Recovery", ("TA0040",)),
            "T1489": ("Service Stop", ("TA0040",)),
            "T1531": ("Account Access Removal", ("TA0040",)),
            "T1083": ("File and Directory Discovery", ("TA0007",)),
            "T1070.004": ("File Deletion", ("TA0005",)),
        }
        self.techniques = {
            identifier: ATTACKTechnique(identifier, name, tactics)
            for identifier, (name, tactics) in entries.items()
        }
