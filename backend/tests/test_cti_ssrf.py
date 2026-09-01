import pytest

from app.services.cti_connectors import SSRFBlockedError, validate_fetch_url


def test_blocks_loopback():
    with pytest.raises(SSRFBlockedError):
        validate_fetch_url("http://127.0.0.1/internal-api")


def test_blocks_cloud_metadata_link_local():
    with pytest.raises(SSRFBlockedError):
        validate_fetch_url("http://169.254.169.254/latest/meta-data/")


def test_blocks_private_network_by_default(monkeypatch):
    monkeypatch.delenv("CTI_ALLOW_PRIVATE_NETWORKS", raising=False)
    with pytest.raises(SSRFBlockedError):
        validate_fetch_url("http://192.168.1.10/feed")


def test_allows_private_network_when_opted_in(monkeypatch):
    monkeypatch.setenv("CTI_ALLOW_PRIVATE_NETWORKS", "true")
    validate_fetch_url("http://192.168.1.10/feed")  # should not raise


def test_blocks_disallowed_scheme():
    with pytest.raises(SSRFBlockedError):
        validate_fetch_url("file:///etc/passwd")


def test_blocks_ftp_scheme():
    with pytest.raises(SSRFBlockedError):
        validate_fetch_url("ftp://example.com/feed")


def test_allows_public_ip_literal():
    validate_fetch_url("http://8.8.8.8/feed")  # should not raise


def test_blocks_unresolvable_host():
    with pytest.raises(SSRFBlockedError):
        validate_fetch_url("http://this-host-should-not-exist.invalid/feed")
