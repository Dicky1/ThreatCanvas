"""Proves notifications are isolated per user (no more shared global list)."""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.core.database import Base, get_db
from app.main import app


@pytest.fixture()
def client():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    Base.metadata.create_all(bind=engine)

    def override_get_db():
        db = TestingSessionLocal()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


def _register_and_login(client, username: str) -> str:
    client.post(
        "/api/v1/auth/register",
        json={
            "username": username,
            "email": f"{username}@example.com",
            "full_name": username,
            "password": "correct-horse-battery-staple",
        },
    )
    response = client.post(
        "/api/v1/auth/login",
        data={"username": username, "password": "correct-horse-battery-staple"},
    )
    return response.json()["access_token"]


def _auth(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def test_users_do_not_see_each_others_notifications(client):
    token_a = _register_and_login(client, "alice")
    token_b = _register_and_login(client, "bob")

    create_response = client.post(
        "/api/v1/notifications",
        json={"title": "Alice only", "message": "secret to alice", "type": "info"},
        headers=_auth(token_a),
    )
    assert create_response.status_code == 201

    alice_list = client.get("/api/v1/notifications", headers=_auth(token_a)).json()
    bob_list = client.get("/api/v1/notifications", headers=_auth(token_b)).json()

    assert len(alice_list) == 1
    assert alice_list[0]["title"] == "Alice only"
    assert bob_list == []


def test_cannot_mark_another_users_notification_as_read(client):
    token_a = _register_and_login(client, "carol")
    token_b = _register_and_login(client, "dave")

    created = client.post(
        "/api/v1/notifications",
        json={"title": "Carol's", "message": "m", "type": "info"},
        headers=_auth(token_a),
    ).json()

    response = client.patch(
        f"/api/v1/notifications/{created['id']}/read", headers=_auth(token_b)
    )
    assert response.status_code == 404

    still_unread = client.get("/api/v1/notifications", headers=_auth(token_a)).json()
    assert still_unread[0]["read"] is False


def test_clear_only_clears_own_notifications(client):
    token_a = _register_and_login(client, "erin")
    token_b = _register_and_login(client, "frank")

    client.post(
        "/api/v1/notifications",
        json={"title": "Erin's", "message": "m", "type": "info"},
        headers=_auth(token_a),
    )
    client.post(
        "/api/v1/notifications",
        json={"title": "Frank's", "message": "m", "type": "info"},
        headers=_auth(token_b),
    )

    client.delete("/api/v1/notifications", headers=_auth(token_a))

    assert client.get("/api/v1/notifications", headers=_auth(token_a)).json() == []
    assert len(client.get("/api/v1/notifications", headers=_auth(token_b)).json()) == 1
