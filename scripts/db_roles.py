"""Create the per-service Postgres roles and store their credentials.

Runs inside the VPC as the db-admin ECS task (see scripts/db_admin.sh), as
the RDS master user. For each role it generates a password, sets it, and
writes {"username", "password"} to the matching Secrets Manager secret, so
the password never leaves AWS. Re-running rotates every password; redeploy
the services afterwards.
"""
import json
import os
import secrets

import psycopg2
from psycopg2 import sql

from app.config import database_url

# secret id suffix -> role -> table privileges. Derived from the SQL each
# service issues; payments-api tests run green against exactly these.
ROLES = {
    "payments-api": ("payments_app", {
        "users": ["SELECT", "INSERT", "UPDATE"],
        "accounts": ["SELECT", "INSERT", "UPDATE"],
        "transactions": ["SELECT", "INSERT"],
        "webhooks": ["SELECT", "INSERT"],
        "audit_log": ["SELECT", "INSERT"],
    }),
    "kyc-api": ("kyc_app", {
        "kyc_records": ["SELECT"],
    }),
}


def apply_roles(cur, passwords):
    """passwords: {role: password}. Idempotent."""
    for _, (role, tables) in ROLES.items():
        ident = sql.Identifier(role)
        cur.execute("SELECT 1 FROM pg_roles WHERE rolname = %s", (role,))
        if cur.fetchone() is None:
            cur.execute(sql.SQL("CREATE ROLE {} LOGIN").format(ident))
        cur.execute(sql.SQL("ALTER ROLE {} WITH LOGIN PASSWORD %s").format(ident), (passwords[role],))
        cur.execute(sql.SQL("REVOKE ALL ON ALL TABLES IN SCHEMA public FROM {}").format(ident))
        cur.execute(sql.SQL("GRANT USAGE ON SCHEMA public TO {}").format(ident))
        for table, privs in tables.items():
            cur.execute(sql.SQL("GRANT {} ON {} TO {}").format(
                sql.SQL(", ").join(sql.SQL(p) for p in privs), sql.Identifier(table), ident))
        if any("INSERT" in p for p in tables.values()):
            cur.execute(sql.SQL("GRANT USAGE ON ALL SEQUENCES IN SCHEMA public TO {}").format(ident))


def main():
    import boto3

    env = os.environ.get("ENVIRONMENT_NAME", "sentinelpay-dev")
    sm = boto3.client("secretsmanager", region_name=os.environ["AWS_REGION"])
    passwords = {role: secrets.token_urlsafe(32) for role, _ in ROLES.values()}

    conn = psycopg2.connect(database_url())
    try:
        with conn, conn.cursor() as cur:
            apply_roles(cur, passwords)
    finally:
        conn.close()

    for service, (role, _) in ROLES.items():
        sm.put_secret_value(
            SecretId=f"{env}/db/{service}",
            SecretString=json.dumps({"username": role, "password": passwords[role]}),
        )
        print(f"role {role}: created/updated, secret {env}/db/{service} written")


if __name__ == "__main__":
    main()
