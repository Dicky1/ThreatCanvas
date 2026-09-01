from __future__ import annotations

import ipaddress
import json
import os
import re
import socket
from typing import Any, Callable
from urllib.error import HTTPError
from urllib.parse import urlparse
from urllib.request import HTTPRedirectHandler, Request, build_opener

from app.schemas.cti import CTIFetchRequest, CTIFetchResult


FetchFn = Callable[[str, str | None], dict[str, Any]]

_ALLOWED_SCHEMES = {"http", "https"}


class SSRFBlockedError(ValueError):
    """Raised when a requested CTI fetch URL targets a disallowed network."""


class _NoRedirectHandler(HTTPRedirectHandler):
    """Refuses to follow redirects, so a validated URL can't be swapped for an
    internal one after the SSRF check has already passed (TOCTOU bypass)."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D102
        return None


def _is_blocked_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address, allow_private: bool) -> bool:
    # Loopback (127.0.0.0/8, ::1), link-local (169.254.0.0/16 - includes the
    # AWS/GCP/Azure metadata address 169.254.169.254), multicast, and other
    # reserved ranges have no legitimate reason to be a CTI feed target and
    # are always blocked. RFC1918 private ranges are blocked by default too,
    # but can be opted back in for deployments with an internal MISP/TAXII
    # server via CTI_ALLOW_PRIVATE_NETWORKS=true.
    if ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_unspecified or ip.is_reserved:
        return True
    if ip.is_private and not allow_private:
        return True
    return False


def validate_fetch_url(url: str) -> None:
    """Raises SSRFBlockedError if `url` is not safe for the server to fetch."""
    parsed = urlparse(url)
    if parsed.scheme not in _ALLOWED_SCHEMES:
        raise SSRFBlockedError(
            f"Unsupported URL scheme {parsed.scheme!r}; only http/https are allowed."
        )
    if not parsed.hostname:
        raise SSRFBlockedError("URL must include a hostname.")

    allow_private = os.getenv("CTI_ALLOW_PRIVATE_NETWORKS", "false").strip().lower() == "true"
    try:
        addrinfo = socket.getaddrinfo(parsed.hostname, None)
    except socket.gaierror as exc:
        raise SSRFBlockedError(f"Could not resolve host {parsed.hostname!r}: {exc}") from exc

    for *_rest, sockaddr in addrinfo:
        ip = ipaddress.ip_address(sockaddr[0])
        if _is_blocked_ip(ip, allow_private):
            raise SSRFBlockedError(
                f"Refusing to fetch {parsed.hostname!r}: resolves to disallowed address {ip}."
            )


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
        validate_fetch_url(url)
        headers = {"Accept": "application/json"}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        request = Request(url, headers=headers)
        opener = build_opener(_NoRedirectHandler)
        try:
            with opener.open(request, timeout=15) as response:
                return json.loads(response.read().decode("utf-8"))
        except HTTPError as error:
            if 300 <= error.code < 400:
                raise SSRFBlockedError(
                    f"Refusing to follow redirect from {url!r} "
                    "(CTI fetch targets must be validated directly, not via redirect)."
                ) from error
            raise
