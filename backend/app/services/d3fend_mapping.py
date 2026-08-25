import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class D3FENDMapping:
    attack_technique: str
    defensive_technique: str
    rationale: str
    source: str
    confidence: float


class D3FENDMappingService:
    """Loads explicit ATT&CK-to-D3FEND mappings without inventing fallbacks."""

    def __init__(
        self,
        mappings: list[dict[str, Any]] | None = None,
        mapping_path: str | os.PathLike[str] | None = None,
    ):
        self._mappings: dict[str, list[D3FENDMapping]] = {}
        if mapping_path is None:
            mapping_path = os.getenv("D3FEND_MAPPING_PATH")
        if mapping_path:
            with Path(mapping_path).open(encoding="utf-8") as stream:
                payload = json.load(stream)
            mappings = payload.get("mappings", payload) if isinstance(payload, dict) else payload
        for mapping in mappings or []:
            self._add(mapping)

    def _add(self, mapping: dict[str, Any]) -> None:
        required = {"attack_technique", "defensive_technique", "rationale", "source", "confidence"}
        missing = required - mapping.keys()
        if missing:
            raise ValueError(f"D3FEND mapping is missing fields: {sorted(missing)}")
        confidence = float(mapping["confidence"])
        if not 0 <= confidence <= 1:
            raise ValueError("D3FEND mapping confidence must be between 0 and 1")
        item = D3FENDMapping(
            attack_technique=str(mapping["attack_technique"]).upper(),
            defensive_technique=str(mapping["defensive_technique"]),
            rationale=str(mapping["rationale"]),
            source=str(mapping["source"]),
            confidence=confidence,
        )
        if any(existing == item for existing in self._mappings.get(item.attack_technique, [])):
            return
        self._mappings.setdefault(item.attack_technique, []).append(item)

    def lookup(self, attack_technique: str) -> tuple[D3FENDMapping, ...]:
        return tuple(self._mappings.get(attack_technique.strip().upper(), ()))