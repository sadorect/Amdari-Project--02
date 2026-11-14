"""Smoke test for kyc-api."""
import pytest
from app.main import create_app


@pytest.fixture
def client():
    app = create_app()
    return app.test_client()


def test_health(client):
    resp = client.get("/health")
    assert resp.status_code == 200


def test_security_headers_on_every_response(client):
    # Found by the ZAP baseline: CSP and Permissions-Policy were missing.
    for path in ("/health", "/no-such-path"):
        h = client.get(path).headers
        assert "default-src 'none'" in h["Content-Security-Policy"]
        assert "geolocation=()" in h["Permissions-Policy"]
        assert h["X-Content-Type-Options"] == "nosniff"
        assert h["Cache-Control"] == "no-store"
