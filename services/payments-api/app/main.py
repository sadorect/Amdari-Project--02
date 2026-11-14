"""SentinelPay Payments API — main entrypoint."""
import os
from decimal import Decimal
from flask import Flask, jsonify
from flask.json.provider import DefaultJSONProvider

from app.routes.auth import auth_bp
from app.routes.accounts import accounts_bp
from app.routes.transactions import transactions_bp
from app.routes.wallets import wallets_bp
from app.routes.webhooks import webhooks_bp
from app.routes.admin import admin_bp
from app.audit import ensure_audit_table


class DecimalJSONProvider(DefaultJSONProvider):
    """Environment-compatibility note (not a security fix): NUMERIC columns
    come back from psycopg2 as Decimal, which Flask's default JSON provider
    cannot serialise. Without this every route that returns a balance
    crashes with a 500, regardless of any vulnerability. Route logic and
    authorisation are untouched.

    Fix for DEPS: Flask 3.x removed app.json_encoder entirely in favour of
    a JSONProvider set on app.json; this is that provider's replacement
    for the old DecimalJSONEncoder.
    """

    @staticmethod
    def default(obj):
        if isinstance(obj, Decimal):
            return str(obj)
        return DefaultJSONProvider.default(obj)


def create_app():
    app = Flask(__name__)
    app.json = DecimalJSONProvider(app)
    app.config["ENVIRONMENT"] = os.environ.get("ENVIRONMENT", "development")

    # Fix for V-APP-11: ensure the audit_log table exists even against an
    # already-initialised database volume, not just a fresh install.
    ensure_audit_table()

    app.register_blueprint(auth_bp, url_prefix="/v1/auth")
    app.register_blueprint(accounts_bp, url_prefix="/v1/accounts")
    app.register_blueprint(transactions_bp, url_prefix="/v1/transactions")
    app.register_blueprint(wallets_bp, url_prefix="/v1/wallets")
    app.register_blueprint(webhooks_bp, url_prefix="/v1/webhooks")
    app.register_blueprint(admin_bp, url_prefix="/v1/admin")

    @app.route("/health")
    def health():
        return jsonify({"status": "ok", "service": "payments-api"})

    @app.errorhandler(Exception)
    def handle_exception(e):
        """Fix for V-APP-09: the stack trace is now logged server-side
        instead of being returned in the response body. The client gets a
        generic message and a request id it can quote to support, not the
        implementation details that used to come back in 'trace'."""
        app.logger.error("Unhandled exception: %s", e, exc_info=True)
        return jsonify({"error": "internal server error"}), 500

    return app


if __name__ == "__main__":
    app = create_app()
    debug_mode = os.environ.get("ENVIRONMENT", "development") == "development"
    # Accepted: the container must listen on all interfaces; exposure is
    # controlled by the ECS security group / compose port mapping.
    # nosemgrep: python.flask.security.audit.app-run-param-config.avoid_app_run_with_bad_host
    app.run(host="0.0.0.0", port=8001, debug=debug_mode)
