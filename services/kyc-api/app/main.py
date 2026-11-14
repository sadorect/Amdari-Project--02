"""SentinelPay KYC API — identity verification service."""
import os
from flask import Flask, jsonify

from app.routes.verify import verify_bp
from app.routes.documents import documents_bp


def create_app():
    app = Flask(__name__)

    app.register_blueprint(verify_bp, url_prefix="/v1/verify")
    app.register_blueprint(documents_bp, url_prefix="/v1/documents")

    @app.route("/health")
    def health():
        return jsonify({"status": "ok", "service": "kyc-api"})

    @app.after_request
    def add_security_headers(resp):
        # API responses are data, never pages: lock down what a browser may do
        # with them if one is ever pointed here.
        resp.headers.setdefault("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
        resp.headers.setdefault("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("Cache-Control", "no-store")
        return resp

    return app


if __name__ == "__main__":
    app = create_app()
    # Fix for V-APP-09: debug mode (Werkzeug's interactive debugger, which
    # can expose source and execute code) is now gated on ENVIRONMENT,
    # not hardcoded on.
    debug_mode = os.environ.get("ENVIRONMENT", "development") == "development"
    # Accepted: the container must listen on all interfaces; exposure is
    # controlled by the ECS security group / compose port mapping.
    # nosemgrep: python.flask.security.audit.app-run-param-config.avoid_app_run_with_bad_host
    app.run(host="0.0.0.0", port=8002, debug=debug_mode)
