"""Builds the compact Atomic Red Team index shipped with ThreatCanvas.

Reads the per-platform CSV indexes from a checkout of
https://github.com/redcanaryco/atomic-red-team (atomics/Indexes/Indexes-CSV)
and writes app/data/atomic_index.json: technique -> atomic tests (GUID, name,
test number, executor, platforms). Atomic Red Team is MIT licensed; its
license is kept next to the data in app/data/ATOMIC_RED_TEAM_LICENSE.txt.

Usage (from backend/):

    python scripts/build_atomic_index.py /path/to/atomic-red-team
"""

import csv
import json
import shutil
import sys
from datetime import UTC, datetime
from pathlib import Path

DATA_DIR = Path(__file__).parent.parent / "app" / "data"
PLATFORM_FILES = {
    "windows": "windows-index.csv",
    "linux": "linux-index.csv",
    "macos": "macos-index.csv",
    "containers": "containers-index.csv",
    "iaas": "iaas-index.csv",
    "azure-ad": "azure-ad-index.csv",
    "office-365": "office-365-index.csv",
    "google-workspace": "google-workspace-index.csv",
    "esxi": "esxi-index.csv",
}


def build(repo: Path) -> dict:
    index_dir = repo / "atomics" / "Indexes" / "Indexes-CSV"
    tests: dict[str, dict] = {}
    for platform, filename in PLATFORM_FILES.items():
        path = index_dir / filename
        if not path.exists():
            continue
        with path.open(encoding="utf-8", newline="") as stream:
            for row in csv.DictReader(stream):
                guid = (row.get("Test GUID") or "").strip()
                technique = (row.get("Technique #") or "").strip().upper()
                if not guid or not technique.startswith("T"):
                    continue
                entry = tests.setdefault(guid, {
                    "guid": guid,
                    "technique": technique,
                    "test_number": int(row.get("Test #") or 0),
                    "name": (row.get("Test Name") or "").strip(),
                    "executor": (row.get("Executor Name") or "").strip(),
                    "platforms": [],
                })
                if platform not in entry["platforms"]:
                    entry["platforms"].append(platform)
    by_technique: dict[str, list[dict]] = {}
    for test in tests.values():
        technique = test.pop("technique")
        by_technique.setdefault(technique, []).append(test)
    for items in by_technique.values():
        items.sort(key=lambda t: t["test_number"])
    return {
        "source": "Atomic Red Team (redcanaryco/atomic-red-team), MIT License",
        "generated_at": datetime.now(UTC).strftime("%Y-%m-%d"),
        "techniques": dict(sorted(by_technique.items())),
    }


def main() -> None:
    if len(sys.argv) != 2:
        print(__doc__, file=sys.stderr)
        sys.exit(2)
    repo = Path(sys.argv[1])
    index = build(repo)
    (DATA_DIR / "atomic_index.json").write_text(json.dumps(index, separators=(",", ":"), ensure_ascii=False), encoding="utf-8")
    license_file = repo / "LICENSE.txt"
    if license_file.exists():
        shutil.copyfile(license_file, DATA_DIR / "ATOMIC_RED_TEAM_LICENSE.txt")
    count = sum(len(v) for v in index["techniques"].values())
    print(f"Wrote {count} atomic tests for {len(index['techniques'])} techniques")


if __name__ == "__main__":
    main()
