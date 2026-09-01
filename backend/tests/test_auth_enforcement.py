"""End-to-end check that protected routers actually require a valid JWT.

Uses its own isolated in-memory SQLite database (via dependency override) so
it never touches the real threatcanvas.db file.
"""

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


def test_health_is_public(client):
    response = client.get("/health")
    assert response.status_code == 200


def test_protected_endpoint_rejects_missing_token(client):
    response = client.get("/api/v1/scenarios")
    assert response.status_code == 401


def test_protected_endpoint_rejects_garbage_token(client):
    response = client.get(
        "/api/v1/scenarios", headers={"Authorization": "Bearer not-a-real-token"}
    )
    assert response.status_code == 401


def test_register_and_login_then_access_protected_endpoint(client):
    register_response = client.post(
        "/api/v1/auth/register",
        json={
            "username": "audit-user",
            "email": "audit-user@example.com",
            "full_name": "Audit User",
            "password": "correct-horse-battery-staple",
        },
    )
    assert register_response.status_code == 201

    login_response = client.post(
        "/api/v1/auth/login",
        data={"username": "audit-user", "password": "correct-horse-battery-staple"},
    )
    assert login_response.status_code == 200
    token = login_response.json()["access_token"]

    authed_response = client.get(
        "/api/v1/scenarios", headers={"Authorization": f"Bearer {token}"}
    )
    assert authed_response.status_code != 401
