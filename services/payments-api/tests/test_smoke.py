"""Smoke tests for payments-api.

NOTE: These are happy-path only. Part of the engagement is to add tests that
demonstrate each fix actually closes the underlying vulnerability.
"""
import json
import pytest

from app.main import create_app


@pytest.fixture
def client():
    app = create_app()
    app.config["TESTING"] = True
    return app.test_client()


def test_health(client):
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.get_json()["status"] == "ok"


def test_unknown_path_is_404_not_500(client):
    # Found by the ZAP baseline: the catch-all Exception handler was turning
    # every routing error into a 500.
    resp = client.get("/no-such-path")
    assert resp.status_code == 404
    assert resp.get_json() == {"error": "not found"}


def test_wrong_method_is_405(client):
    resp = client.post("/health")
    assert resp.status_code == 405
