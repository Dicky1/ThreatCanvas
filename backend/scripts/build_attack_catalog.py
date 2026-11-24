"""Builds the compact ATT&CK catalog shipped with ThreatCanvas.

The full MITRE ATT&CK Enterprise STIX bundle is ~55MB and is not committed
(see .gitignore). This script reduces it to the fields ThreatCanvas actually
uses (technique ID, name, tactic IDs, data sources, deprecation, version) and
writes `app/data/attack_catalog.json` (a few hundred KB), which IS committed.

That way a fresh clone validates every Enterprise technique with the official
tactic mappings, without downloading anything.

Usage (run from backend/):

    python scripts/build_attack_catalog.py [path/to/enterprise-attack.json]

Defaults to `app/data/enterprise-attack.json`. `scripts/fetch_attack_data.py`
calls this automatically after downloading a fresh bundle.
"""

import json
import sys
from datetime import UTC, datetime
from pathlib import Path

DATA_DIR = Path(__file__).parent.parent / "app" / "data"
DEFAULT_SOURCE = DATA_DIR / "enterprise-attack.json"
DEST_PATH = DATA_DIR / "attack_catalog.json"

TACTIC_IDS = {
    "reconnaissance": "TA0043",
    "resource-development": "TA0042",
    "initial-access": "TA0001",
    "execution": "TA0002",
    "persistence": "TA0003",
    "privilege-escalation": "TA0004",
    "defense-evasion": "TA0005",
    "credential-access": "TA0006",
    "discovery": "TA0007",
    "lateral-movement": "TA0008",
    "collection": "TA0009",
    "command-and-control": "TA0011",
    "exfiltration": "TA0010",
    "impact": "TA0040",
    # ATT&CK v18+ renamed Defense Evasion to Stealth and split out Defense Impairment.
    "stealth": "TA0005",
    "defense-impairment": "TA0112",
}


def _external_id(obj: dict) -> str | None:
    for ref in obj.get("external_references", []):
        identifier = ref.get("external_id", "")
        if ref.get("source_name") == "mitre-attack" and identifier.startswith("T"):
            return identifier.upper()
    return None


def _tactic_ids(bundle: dict) -> dict[str, str]:
    """Shortname -> TA id, taken from the bundle's own x-mitre-tactic objects."""
    mapping = dict(TACTIC_IDS)
    for obj in bundle.get("objects", []):
        if obj.get("type") != "x-mitre-tactic" or obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack" and ref.get("external_id", "").startswith("TA"):
                mapping[obj.get("x_mitre_shortname", "")] = ref["external_id"]
    return mapping


def build(bundle: dict) -> dict:
    attack_version = None
    techniques: dict[str, dict] = {}
    tactic_ids = _tactic_ids(bundle)
    tactics_meta = {
        ref_id: name
        for obj in bundle.get("objects", [])
        if obj.get("type") == "x-mitre-tactic" and not obj.get("revoked")
        for ref_id, name in [(tactic_ids.get(obj.get("x_mitre_shortname", "")), obj.get("name"))]
        if ref_id
    }
    for obj in bundle.get("objects", []):
        if obj.get("type") == "x-mitre-collection":
            attack_version = obj.get("x_mitre_version") or attack_version
        if obj.get("type") != "attack-pattern":
            continue
        technique_id = _external_id(obj)
        if not technique_id:
            continue
        tactics = [
            tactic_ids[phase["phase_name"]]
            for phase in obj.get("kill_chain_phases", [])
            if phase.get("kill_chain_name") == "mitre-attack"
            and phase.get("phase_name") in tactic_ids
        ]
        deprecated = bool(obj.get("revoked") or obj.get("x_mitre_deprecated"))
        existing = techniques.get(technique_id)
        # A revoked object can share an ID with its live replacement: keep the live one.
        if existing and not existing["deprecated"] and deprecated:
            continue
        techniques[technique_id] = {
            "name": obj.get("name", technique_id),
            "tactics": tactics,
            "data_sources": sorted(set(obj.get("x_mitre_data_sources", []))),
            "deprecated": deprecated,
            "version": obj.get("x_mitre_version"),
        }
    return {
        "source": "MITRE ATT&CK Enterprise (attack-stix-data)",
        "attack_version": attack_version,
        "generated_at": datetime.now(UTC).strftime("%Y-%m-%d"),
        "tactics": dict(sorted(tactics_meta.items())),
        "techniques": dict(sorted(techniques.items())),
    }


def main(source: Path | None = None) -> None:
    if source is None:
        source = Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_SOURCE
    if not source.exists():
        print(f"Bundle not found: {source}. Run scripts/fetch_attack_data.py first.", file=sys.stderr)
        sys.exit(1)
    with source.open(encoding="utf-8") as stream:
        catalog = build(json.load(stream))
    DEST_PATH.write_text(json.dumps(catalog, separators=(",", ":"), ensure_ascii=False), encoding="utf-8")
    size_kb = DEST_PATH.stat().st_size / 1024
    print(
        f"Wrote {len(catalog['techniques'])} techniques (ATT&CK v{catalog['attack_version']}) "
        f"to {DEST_PATH} ({size_kb:.0f} KB)"
    )


if __name__ == "__main__":
    main()
