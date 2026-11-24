"""Downloads the official MITRE ATT&CK Enterprise STIX 2.1 bundle.

A compact catalog of every Enterprise technique (`app/data/attack_catalog.json`)
is already committed, so this is only needed to refresh to a newer ATT&CK
release or to get the full STIX objects. After downloading it also rebuilds
the compact catalog via `scripts/build_attack_catalog.py`.

The downloaded file is intentionally NOT committed to git (it is ~50MB and
regenerable) - see .gitignore. Run this once after cloning, or whenever you
want to refresh to the latest ATT&CK release:

    python scripts/fetch_attack_data.py

`ATTACKKnowledgeService` auto-detects the file at
`app/data/enterprise-attack.json` with no further configuration needed. To
use a different location or a pinned/offline copy instead, set the
`ATTACK_STIX_PATH` environment variable to point at it.
"""

import json
import os
import shutil
import sys
import urllib.request
from pathlib import Path

SOURCE_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
    "master/enterprise-attack/enterprise-attack.json"
)
DEST_PATH = Path(__file__).parent.parent / "app" / "data" / "enterprise-attack.json"


def main() -> None:
    print(f"Downloading ATT&CK Enterprise STIX bundle from:\n  {SOURCE_URL}")
    DEST_PATH.parent.mkdir(parents=True, exist_ok=True)
    partial = DEST_PATH.with_suffix(".json.part")
    try:
        with urllib.request.urlopen(SOURCE_URL, timeout=120) as response, partial.open("wb") as out:  # noqa: S310 - fixed https URL
            shutil.copyfileobj(response, out)
        # Only replace the existing file with a complete, parseable bundle.
        with partial.open(encoding="utf-8") as stream:
            bundle = json.load(stream)
        if bundle.get("type") != "bundle" or not bundle.get("objects"):
            raise ValueError("downloaded file is not an ATT&CK STIX bundle")
        os.replace(partial, DEST_PATH)
    except Exception as exc:  # noqa: BLE001 - surface any network/IO failure to the user
        partial.unlink(missing_ok=True)
        print(f"Download failed: {exc}", file=sys.stderr)
        sys.exit(1)

    size_mb = DEST_PATH.stat().st_size / (1024 * 1024)
    print(f"Saved to {DEST_PATH} ({size_mb:.1f} MB)")

    # Refresh the committed compact catalog from the new bundle.
    sys.path.insert(0, str(Path(__file__).parent))
    import build_attack_catalog

    build_attack_catalog.main(DEST_PATH)


if __name__ == "__main__":
    main()
