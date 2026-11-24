"""JWT handling after replacing python-jose (GHSA-3qf3-8w2g-rqmx) with PyJWT."""

import base64
import hashlib
import hmac
import json
import warnings
from datetime import datetime, timedelta, timezone

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.warnings import InsecureKeyLengthWarning

from app.core.config import Settings, settings
from app.core.security import create_access_token, decode_access_token


def _future(minutes=5):
    return datetime.now(timezone.utc) + timedelta(minutes=minutes)


def _b64(data: dict) -> str:
    return base64.urlsafe_b64encode(json.dumps(data).encode()).rstrip(b"=").decode()


def test_round_trip_returns_subject():
    assert decode_access_token(create_access_token("user-123")) == "user-123"


def test_expired_token_is_rejected():
    token = jwt.encode(
        {"sub": "user-123", "exp": datetime.now(timezone.utc) - timedelta(seconds=5)},
        settings.SECRET_KEY,
        algorithm=settings.ALGORITHM,
    )
    assert decode_access_token(token) is None


def test_wrong_key_and_tampered_tokens_are_rejected():
    forged = jwt.encode({"sub": "admin", "exp": _future()}, "attacker-key-" + "x" * 32, algorithm="HS256")
    assert decode_access_token(forged) is None

    header, _, signature = create_access_token("user-123").split(".")
    tampered = ".".join([header, _b64({"sub": "admin", "exp": int(_future().timestamp())}), signature])
    assert decode_access_token(tampered) is None


def test_alg_none_is_rejected():
    unsigned = f"{_b64({'alg': 'none', 'typ': 'JWT'})}.{_b64({'sub': 'admin', 'exp': int(_future().timestamp())})}."
    assert decode_access_token(unsigned) is None


def test_other_hmac_algorithm_is_rejected():
    # The test secret is short for SHA-512; that warning is expected here.
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", InsecureKeyLengthWarning)
        token = jwt.encode({"sub": "user-123", "exp": _future()}, settings.SECRET_KEY, algorithm="HS512")
    assert decode_access_token(token) is None


def test_public_key_as_hmac_secret_cannot_forge_tokens():
    """The python-jose bug: an attacker signs HS256 with a DER public key."""
    public_der = rsa.generate_private_key(public_exponent=65537, key_size=2048).public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    header = _b64({"alg": "HS256", "typ": "JWT"})
    payload = _b64({"sub": "admin", "exp": int(_future().timestamp())})
    signature = base64.urlsafe_b64encode(
        hmac.new(public_der, f"{header}.{payload}".encode(), hashlib.sha256).digest()
    ).rstrip(b"=").decode()
    assert decode_access_token(f"{header}.{payload}.{signature}") is None


@pytest.mark.parametrize("claims", [{"sub": "user-123"}, {"exp": "later"}, {"sub": "", "exp": None}])
def test_tokens_missing_required_claims_are_rejected(claims):
    payload = {key: (_future() if key == "exp" else value) for key, value in claims.items()}
    token = jwt.encode(payload, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    assert decode_access_token(token) is None


@pytest.mark.parametrize("algorithm", ["none", "RS256", "ES256"])
def test_non_hmac_algorithm_setting_refuses_to_start(algorithm):
    with pytest.raises(RuntimeError, match="ALGORITHM"):
        Settings(ALGORITHM=algorithm, ENVIRONMENT="test").validate_security()
