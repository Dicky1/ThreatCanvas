import http.server
import ipaddress
import socket
import threading

import pytest

from app.services import safe_fetch
from app.services.safe_fetch import FetchBlockedError, is_disallowed_ip, resolve_public


@pytest.mark.parametrize("address", [
    "127.0.0.1", "169.254.169.254", "10.1.2.3", "192.168.1.1", "100.64.0.1", "0.0.0.0", "224.0.0.1",
    "::1", "fe80::1", "fc00::1", "::ffff:127.0.0.1", "::ffff:169.254.169.254", "2002:7f00:1::1", "2001:0::1",
])
def test_internal_addresses_are_refused(address):
    assert is_disallowed_ip(ipaddress.ip_address(address))


def test_public_and_opt_in_private():
    assert not is_disallowed_ip(ipaddress.ip_address("8.8.8.8"))
    assert not is_disallowed_ip(ipaddress.ip_address("2606:4700:4700::1111"))
    assert not is_disallowed_ip(ipaddress.ip_address("10.0.0.5"), allow_private=True)
    assert is_disallowed_ip(ipaddress.ip_address("169.254.169.254"), allow_private=True)
    assert is_disallowed_ip(ipaddress.ip_address("100.64.0.1"), allow_private=True)


@pytest.mark.parametrize("url,message", [
    ("file:///etc/passwd", "Only http"),
    ("gopher://x", "Only http"),
    ("http://user:pass@example.com/", "Credentials"),
    ("http://example.com:6379/", "Port 6379"),
    ("http:///nohost", "hostname"),
])
def test_url_shape_is_validated(url, message):
    with pytest.raises(FetchBlockedError, match=message):
        resolve_public(url)


@pytest.fixture()
def local_server():
    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            if self.path == "/redirect":
                self.send_response(302)
                self.send_header("Location", "http://metadata.test/latest/meta-data/")
                self.end_headers()
                return
            body = b"<html><body><article>" + self.headers.get("Host", "").encode() + b"</article></body></html>"
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield server.server_address[1]
    server.shutdown()


@pytest.fixture()
def fake_dns(monkeypatch, local_server):
    """cti.test resolves to a public IP; connections to it are routed to the local server."""
    table = {"cti.test": "93.184.216.34", "metadata.test": "169.254.169.254"}
    connected = []

    real_getaddrinfo = socket.getaddrinfo

    def getaddrinfo(host, port, *args, **kwargs):
        if host == "127.0.0.1":  # the redirected test connection itself
            return real_getaddrinfo(host, port, *args, **kwargs)
        if host not in table:
            raise socket.gaierror("unknown")
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (table[host], port))]

    real_connect = socket.create_connection

    def create_connection(address, timeout=None, *args, **kwargs):
        connected.append(address[0])
        return real_connect(("127.0.0.1", local_server), timeout)

    monkeypatch.setattr(safe_fetch.socket, "getaddrinfo", getaddrinfo)
    monkeypatch.setattr(safe_fetch.socket, "create_connection", create_connection)
    return connected


def test_connects_to_the_validated_ip_with_original_host_header(fake_dns):
    result = safe_fetch.fetch("http://cti.test/report")
    assert fake_dns == ["93.184.216.34"]  # pinned: no second DNS lookup by the HTTP client
    assert b"cti.test" in result.body and result.content_type == "text/html"


def test_redirect_to_internal_address_is_blocked(fake_dns):
    with pytest.raises(FetchBlockedError, match="non-public"):
        safe_fetch.fetch("http://cti.test/redirect")


def test_response_size_cap(fake_dns):
    with pytest.raises(FetchBlockedError, match="exceeds"):
        safe_fetch.fetch("http://cti.test/report", max_bytes=10)
