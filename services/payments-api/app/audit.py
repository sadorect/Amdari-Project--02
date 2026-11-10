"""Fix for V-APP-11: structured audit logging for money movement and other
sensitive operations (wallet credit/debit, profile updates, registration,
webhook registration) — previously none of these left any record of who
did what, when, or against which resource.

Writes to a dedicated audit_log table rather than just stdout, so entries
survive container restarts and can be queried; ensure_audit_table() is
called once at app startup so this works against an already-initialised
database volume, not just a fresh one (seed/schema.sql also creates the
table for clean installs).
"""
import json
import logging

from app.db import get_connection

logger = logging.getLogger("audit")


def ensure_audit_table():
    conn = get_connection()
    cur = conn.cursor()
    try:
        # A least-privilege service role (no CREATE on the schema) fails on
        # CREATE TABLE IF NOT EXISTS even when the table exists, so only
        # attempt the create when the migration has not already made it.
        cur.execute("SELECT to_regclass('public.audit_log')")
        if cur.fetchone()["to_regclass"] is not None:
            return
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS audit_log (
                id              SERIAL PRIMARY KEY,
                actor_user_id   INTEGER,
                action          VARCHAR(100) NOT NULL,
                resource_type   VARCHAR(50) NOT NULL,
                resource_id     VARCHAR(100),
                metadata        JSONB,
                created_at      TIMESTAMP DEFAULT NOW()
            )
            """
        )
        conn.commit()
    finally:
        cur.close()
        conn.close()


def log_event(actor_user_id, action: str, resource_type: str, resource_id, metadata: dict = None):
    """Best-effort: a failure to write the audit record must never fail the
    request it's describing, so this swallows (but does not hide — it still
    logs) its own errors rather than propagating them."""
    conn = get_connection()
    cur = conn.cursor()
    try:
        cur.execute(
            "INSERT INTO audit_log (actor_user_id, action, resource_type, resource_id, metadata) "
            "VALUES (%s, %s, %s, %s, %s)",
            (actor_user_id, action, resource_type, str(resource_id), json.dumps(metadata or {}, default=str)),
        )
        conn.commit()
    except Exception:
        logger.exception("failed to write audit log entry for action=%s resource_id=%s", action, resource_id)
    finally:
        cur.close()
        conn.close()
