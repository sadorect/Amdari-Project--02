"""Change-password route: needs the current password, enforces length, and
actually changes what login accepts."""
import uuid

import pytest

from app.main import create_app


@pytest.fixture
def client():
    app = create_app()
    app.config["TESTING"] = True
    return app.test_client()


def _user(client):
    email = f"pw-{uuid.uuid4().hex[:10]}@example.test"
    client.post("/v1/auth/register", json={"email": email, "password": "Original-pass-1"})
    token = client.post("/v1/auth/login", json={"email": email, "password": "Original-pass-1"}).get_json()["token"]
    return email, {"Authorization": f"Bearer {token}"}


def test_requires_auth(client):
    r = client.post("/v1/auth/password", json={"current_password": "a", "new_password": "b" * 14})
    assert r.status_code == 401


def test_change_then_login_with_new_only(client):
    email, hdr = _user(client)
    r = client.post("/v1/auth/password", headers=hdr,
                    json={"current_password": "Original-pass-1", "new_password": "Brand-new-pass-2"})
    assert r.status_code == 200
    assert client.post("/v1/auth/login", json={"email": email, "password": "Original-pass-1"}).status_code == 401
    assert client.post("/v1/auth/login", json={"email": email, "password": "Brand-new-pass-2"}).status_code == 200


def test_wrong_current_password_rejected(client):
    email, hdr = _user(client)
    r = client.post("/v1/auth/password", headers=hdr,
                    json={"current_password": "not-the-password", "new_password": "Brand-new-pass-2"})
    assert r.status_code == 401
    assert client.post("/v1/auth/login", json={"email": email, "password": "Original-pass-1"}).status_code == 200


def test_short_new_password_rejected(client):
    _, hdr = _user(client)
    r = client.post("/v1/auth/password", headers=hdr,
                    json={"current_password": "Original-pass-1", "new_password": "short"})
    assert r.status_code == 400
