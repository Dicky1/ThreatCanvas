"""SSRF-safe HTTP(S) fetching for user-supplied URLs (CTI reports).

- only http/https, ports 80/443/8080/8443
- the hostname is resolved once; every resolved address must be public
  (loopback, link-local/metadata, private, CGNAT, multicast, reserved and
  IPv4-mapped variants are refused; RFC1918 can be allowed explicitly via
  CTI_ALLOW_PRIVATE_NETWORKS=true)
- the connection goes to the validated IP (no second DNS lookup, so DNS
  rebinding cannot swap the target), while TLS SNI and certificate checks
  still use the original hostname
- redirects are followed manually (max 3) and every hop is re-validated
- response size and time are capped
"""

from __future__ import annotations

import http.client
import ipaddress
import os
import socket
import ssl
from dataclasses import dataclass
from urllib.parse import urljoin, urlparse

ALLOWED_PORTS = {80, 443, 8080, 8443}
MAX_REDIRECTS = 3
DEFAULT_MAX_BYTES = 10 * 1024 * 1024
TIMEOUT_SECONDS = 15
USER_AGENT = "ThreatCanvas-CTI-Fetcher/1.0"


class FetchBlockedError(ValueError):
    """The URL targets a disallowed destination or violates a limit."""


@dataclass
class FetchResult:
    url: str
    status: int
    content_type: str
    body: bytes


def is_disallowed_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address, allow_private: bool = False) -> bool:
    if isinstance(ip, ipaddress.IPv6Address):
        if ip.ipv4_mapped is not None:
            return is_disallowed_ip(ip.ipv4_mapped, allow_private)
        if ip.sixtofour is not None:
            return is_disallowed_ip(ip.sixtofour, allow_private)
        if ip.teredo is not None:
            return True
    if ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_unspecified or ip.is_reserved:
        return True
    if ip.is_global:
        return False
    # Non-global: RFC1918 / ULA may be allowed for internal feeds, nothing else.
    return not (allow_private and ip.is_private)


def _allow_private() -> bool:
    return os.getenv("CTI_ALLOW_PRIVATE_NETWORKS", "false").strip().lower() == "true"


def resolve_public(url: str) -> tuple[str, str, int, str]:
    """Validate a URL; returns (scheme, host, port, ip)."""
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise FetchBlockedError("Only http and https URLs are allowed")
    if not parsed.hostname:
        raise FetchBlockedError("URL must include a hostname")
    if parsed.username or parsed.password:
        raise FetchBlockedError("Credentials in URLs are not allowed")
    try:
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
    except ValueError as error:
        raise FetchBlockedError("Invalid port") from error
    if port not in ALLOWED_PORTS:
        raise FetchBlockedError(f"Port {port} is not allowed")
    try:
        infos = socket.getaddrinfo(parsed.hostname, port, type=socket.SOCK_STREAM)
    except socket.gaierror as error:
        raise FetchBlockedError(f"Could not resolve host {parsed.hostname!r}") from error
    addresses = {info[4][0] for info in infos}
    allow_private = _allow_private()
    for address in addresses:
        if is_disallowed_ip(ipaddress.ip_address(address), allow_private):
            raise FetchBlockedError(f"Refusing to fetch {parsed.hostname!r}: resolves to a non-public address")
    # Prefer IPv4 for predictability; every address was validated above.
    ip = sorted(addresses, key=lambda a: (":" in a, a))[0]
    return parsed.scheme, parsed.hostname, port, ip


class _PinnedHTTPConnection(http.client.HTTPConnection):
    def __init__(self, host: str, ip: str, port: int, timeout: float):
        super().__init__(host, port=port, timeout=timeout)
        self._ip = ip

    def connect(self) -> None:
        self.sock = socket.create_connection((self._ip, self.port), self.timeout)


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, host: str, ip: str, port: int, timeout: float):
        super().__init__(host, port=port, timeout=timeout, context=ssl.create_default_context())
        self._ip = ip

    def connect(self) -> None:
        sock = socket.create_connection((self._ip, self.port), self.timeout)
        self.sock = self._context.wrap_socket(sock, server_hostname=self.host)


def fetch(url: str, *, max_bytes: int = DEFAULT_MAX_BYTES, accept: str = "*/*") -> FetchResult:
    current = url
    for _hop in range(MAX_REDIRECTS + 1):
        scheme, host, port, ip = resolve_public(current)
        connection_cls = _PinnedHTTPSConnection if scheme == "https" else _PinnedHTTPConnection
        connection = connection_cls(host, ip, port, TIMEOUT_SECONDS)
        parsed = urlparse(current)
        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query
        try:
            connection.request("GET", path, headers={"Host": parsed.netloc, "User-Agent": USER_AGENT, "Accept": accept})
            response = connection.getresponse()
            if 300 <= response.status < 400 and response.getheader("Location"):
                current = urljoin(current, response.getheader("Location"))
                continue
            length = response.getheader("Content-Length")
            if length and length.isdigit() and int(length) > max_bytes:
                raise FetchBlockedError(f"Response exceeds {max_bytes // (1024 * 1024)} MB")
            body = response.read(max_bytes + 1)
            if len(body) > max_bytes:
                raise FetchBlockedError(f"Response exceeds {max_bytes // (1024 * 1024)} MB")
            if response.status >= 400:
                raise FetchBlockedError(f"Remote server returned HTTP {response.status}")
            return FetchResult(current, response.status, (response.getheader("Content-Type") or "").lower(), body)
        except (OSError, http.client.HTTPException, ssl.SSLError) as error:
            raise FetchBlockedError(f"Could not fetch URL: {type(error).__name__}") from error
        finally:
            connection.close()
    raise FetchBlockedError(f"Too many redirects (max {MAX_REDIRECTS})")
