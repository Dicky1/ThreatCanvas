"""Downloads the official MITRE ATT&CK Enterprise STIX 2.1 bundle.

This unlocks full ATT&CK technique/sub-technique validation (600+ techniques)
instead of the small ~44-technique compatibility catalog that ships as a
built-in fallback in `app/services/attack_knowledge.py`.

The downloaded file is intentionally NOT committed to git (it is ~50MB and
regenerable) - see .gitignore. Run this once after cloning, or whenever you
want to refresh to the latest ATT&CK release:

    python scripts/fetch_attack_data.py

`ATTACKKnowledgeService` auto-detects the file at
`app/data/enterprise-attack.json` with no further configuration needed. To
use a different location or a pinned/offline copy instead, set the
`ATTACK_STIX_PATH` environment variable to point at it.
"""

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
    try:
        urllib.request.urlretrieve(SOURCE_URL, DEST_PATH)
    except Exception as exc:  # noqa: BLE001 - surface any network/IO failure to the user
        print(f"Download failed: {exc}", file=sys.stderr)
        sys.exit(1)

    size_mb = DEST_PATH.stat().st_size / (1024 * 1024)
    print(f"Saved to {DEST_PATH} ({size_mb:.1f} MB)")


if __name__ == "__main__":
    main()
