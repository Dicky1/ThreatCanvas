import os
import secrets

os.environ["ENVIRONMENT"] = "test"

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from sqlalchemy import create_engine  # noqa: E402
from sqlalchemy.orm import sessionmaker  # noqa: E402
from sqlalchemy.pool import StaticPool  # noqa: E402


@pytest.fixture()
def db_engine():
    import app.main  # noqa: F401 - registers every model on Base.metadata
    from app.core.database import Base

    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(bind=engine)
    return engine


@pytest.fixture()
def api_client(db_engine):
    """TestClient backed by an isolated in-memory database."""
    from app.core.database import get_db
    from app.main import app

    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=db_engine)

    def override_get_db():
        db = TestingSessionLocal()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as client:
        yield client
    app.dependency_overrides.clear()


@pytest.fixture()
def make_user(api_client):
    """Register + log in a user; returns auth headers."""

    def _make(username: str) -> dict[str, str]:
        password = secrets.token_urlsafe(18)
        response = api_client.post(
            "/api/v1/auth/register",
            json={"username": username, "email": f"{username}@example.com", "full_name": username, "password": password},
        )
        assert response.status_code == 201, response.text
        token = api_client.post("/api/v1/auth/login", data={"username": username, "password": password}).json()["access_token"]
        return {"Authorization": f"Bearer {token}"}

    return _make
