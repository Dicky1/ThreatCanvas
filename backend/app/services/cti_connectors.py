from __future__ import annotations

import json
import re
from typing import Any, Callable
from urllib.request import Request, urlopen

from app.schemas.cti import CTIFetchRequest, CTIFetchResult


FetchFn = Callable[[str, str | None], dict[str, Any]]


class CTIConnectorService:
    """Normalizes CTI from STIX-like payloads and lightweight connector fetches."""

    def __init__(self, fetcher: FetchFn | None = None):
        self.fetcher = fetcher or self._fetch_json

    def fetch(self, request: CTIFetchRequest) -> CTIFetchResult:
        payload = request.payload
        if payload is None:
            if not request.url:
                raise ValueError("Connector request requires either payload or url")
            payload = self.fetcher(request.url, request.token)

        bundle = self._normalize(request.source_type, payload)
        objects = bundle.get("objects", [])
        techniques = sorted(set(self._extract_techniques(bundle)))
        indicators = self._extract_indicators(bundle)
        return CTIFetchResult(
            source_type=request.source_type,
            object_count=len(objects),
            technique_count=len(techniques),
            indicator_count=len(indicators),
            techniques=techniques,
            indicators=indicators,
            normalized_bundle=bundle,
        )

    def _normalize(self, source_type: str, payload: dict[str, Any]) -> dict[str, Any]:
        if payload.get("type") == "bundle" and isinstance(payload.get("objects"), list):
            return payload
        if source_type == "misp":
            return self._misp_to_stix_like(payload)
        if source_type == "opencti":
            return self._opencti_to_stix_like(payload)
        if source_type == "taxii":
            objects = payload.get("objects") or payload.get("more", {}).get("objects")
            if isinstance(objects, list):
                return {"type": "bundle", "id": "bundle--taxii-import", "objects": objects}
        raise ValueError(f"Unsupported or unreadable CTI payload for source type: {source_type}")

    @staticmethod
    def _misp_to_stix_like(payload: dict[str, Any]) -> dict[str, Any]:
        event = payload.get("Event", payload)
        attributes = event.get("Attribute", []) if isinstance(event, dict) else []
        objects = []
        for index, attribute in enumerate(attributes):
            value = str(attribute.get("value", ""))
            attr_type = str(attribute.get("type", "indicator"))
            objects.append(
                {
                    "type": "indicator",
                    "id": f"indicator--misp-{index}",
                    "name": value,
                    "pattern": f"[x-threatcanvas:{attr_type} = '{value}']",
                }
            )
        return {"type": "bundle", "id": "bundle--misp-import", "objects": objects}

    @staticmethod
    def _opencti_to_stix_like(payload: dict[str, Any]) -> dict[str, Any]:
        data = payload.get("data", payload)
        edges = data.get("stixCoreObjects", {}).get("edges", []) if isinstance(data, dict) else []
        objects = [edge.get("node") for edge in edges if isinstance(edge, dict) and isinstance(edge.get("node"), dict)]
        return {"type": "bundle", "id": "bundle--opencti-import", "objects": objects}

    @staticmethod
    def _extract_techniques(bundle: dict[str, Any]) -> list[str]:
        rendered = json.dumps(bundle)
        return re.findall(r"T\d{4}(?:\.\d{3})?", rendered.upper())

    @staticmethod
    def _extract_indicators(bundle: dict[str, Any]) -> list[dict[str, Any]]:
        indicators = []
        for obj in bundle.get("objects", []):
            if not isinstance(obj, dict) or obj.get("type") != "indicator":
                continue
            indicators.append(
                {
                    "id": obj.get("id"),
                    "name": obj.get("name"),
                    "pattern": obj.get("pattern"),
                }
            )
        return indicators

    @staticmethod
    def _fetch_json(url: str, token: str | None) -> dict[str, Any]:
        headers = {"Accept": "application/json"}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        request = Request(url, headers=headers)
        with urlopen(request, timeout=15) as response:
            return json.loads(response.read().decode("utf-8"))
