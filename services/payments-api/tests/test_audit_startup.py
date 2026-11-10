"""ensure_audit_table() runs at every app start. With per-service DB roles
the service role has no CREATE on the schema, and CREATE TABLE IF NOT EXISTS
fails on privilege even when the table already exists."""
import pytest

from app import audit
from app.db import get_connection


@pytest.fixture
def probe_role():
    conn = get_connection()
    conn.autocommit = True
    cur = conn.cursor()
    cur.execute(
        "DO $$ BEGIN IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname='audit_probe') "
        "THEN CREATE ROLE audit_probe NOLOGIN; END IF; END $$"
    )
    cur.execute("GRANT USAGE ON SCHEMA public TO audit_probe")
    try:
        yield
    finally:
        cur.execute("REVOKE USAGE ON SCHEMA public FROM audit_probe")
        cur.execute("DROP ROLE IF EXISTS audit_probe")
        cur.close()
        conn.close()


def test_startup_needs_no_create_privilege_when_table_exists(monkeypatch, probe_role):
    def restricted_connection():
        conn = get_connection()
        cur = conn.cursor()
        cur.execute("SET ROLE audit_probe")
        cur.close()
        return conn

    monkeypatch.setattr(audit, "get_connection", restricted_connection)
    audit.ensure_audit_table()  # raised "permission denied for schema public" before the fix
