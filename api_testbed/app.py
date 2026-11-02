import os
import traceback
from flask import Flask, jsonify, request, make_response
from .config import Config
from .database import init_db
from .seed_data import seed_database
from .routes.auth import auth_bp
from .routes.users import users_bp
from .routes.documents import documents_bp
from .routes.orders import orders_bp
from .routes.products import products_bp
from .routes.admin import admin_bp
from .routes.tools import tools_bp

def create_app(secure_mode=None):
    """Flask application factory."""
    app = Flask(__name__)
    
    if secure_mode is not None:
        Config.SECURE_MODE = secure_mode

    if Config.SECURE_MODE:
        try:
            import werkzeug.serving
            werkzeug.serving.WSGIRequestHandler.server_version = "Protected-API-Gateway"
            werkzeug.serving.WSGIRequestHandler.sys_version = ""
        except Exception:
            pass

        class StripServerHeaderMiddleware:
            def __init__(self, wsgi_app):
                self.wsgi_app = wsgi_app
            def __call__(self, environ, start_response):
                def custom_start_response(status, headers, exc_info=None):
                    clean_headers = [(k, v) for k, v in headers if k.lower() not in ('server', 'x-powered-by')]
                    clean_headers.append(('Server', 'Protected-API-Gateway'))
                    return start_response(status, clean_headers, exc_info)
                return self.wsgi_app(environ, custom_start_response)
        app.wsgi_app = StripServerHeaderMiddleware(app.wsgi_app)
    
    app.config["SECRET_KEY"] = Config.SECRET_KEY
    app.config["DEBUG"] = not Config.SECURE_MODE

    # Ensure DB is created and seeded
    if not os.path.exists(Config.DATABASE_PATH):
        seed_database()

    # Register Blueprints
    app.register_blueprint(auth_bp)
    app.register_blueprint(users_bp)
    app.register_blueprint(documents_bp)
    app.register_blueprint(orders_bp)
    app.register_blueprint(products_bp)
    app.register_blueprint(admin_bp)
    app.register_blueprint(tools_bp)

    @app.route("/", methods=["GET"])
    def index():
        mode_str = "SECURE (Remediated)" if Config.SECURE_MODE else "VULNERABLE (Assessment Testbed)"
        return jsonify({
            "name": "ShopVault Enterprise REST API",
            "version": "v1.4.2",
            "security_mode": mode_str,
            "owasp_target_coverage": [
                "API1:2023 - Broken Object Level Authorization (BOLA/IDOR)",
                "API2:2023 - Broken Authentication (JWT none-alg & weak secret)",
                "API3:2023 - Broken Object Property Level Authorization (Mass Assignment & Excessive Data)",
                "API4:2023 - Unrestricted Resource Consumption (Rate Limiting)",
                "API5:2023 - Broken Function Level Authorization (BFLA Admin Access)",
                "API8:2023 - Security Misconfiguration (CORS, Missing Headers, Debug Exposure)",
                "CWE-89 - SQL Injection (Search endpoint)",
                "CWE-78 - OS Command Injection (Diagnostics Ping utility)"
            ],
            "endpoints": {
                "auth": ["/api/v1/auth/login", "/api/v1/auth/register"],
                "users": ["/api/v1/users/<id>/profile"],
                "documents": ["/api/v1/documents", "/api/v1/documents/<id>"],
                "orders": ["/api/v1/orders", "/api/v1/orders/<id>"],
                "products": ["/api/v1/products", "/api/v1/products/search"],
                "admin": ["/api/v1/admin/users", "/api/v1/admin/system/status", "/api/v1/admin/export-db"],
                "tools": ["/api/v1/tools/ping", "/api/v1/tools/debug/crash", "/api/v1/tools/debug/config"]
            }
        }), 200

    @app.after_request
    def apply_security_headers(response):
        """
        After-request handler to demonstrate Security Misconfigurations vs Hardened Headers.
        """
        origin = request.headers.get("Origin")

        if Config.SECURE_MODE:
            # SECURE: Strict CORS and OWASP security headers
            if origin in ("http://127.0.0.1:5000", "http://localhost:5000"):
                response.headers["Access-Control-Allow-Origin"] = origin
                response.headers["Access-Control-Allow-Credentials"] = "true"
            else:
                response.headers["Access-Control-Allow-Origin"] = "null"

            response.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS"
            response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"

            # Defense-in-depth security headers
            response.headers["X-Content-Type-Options"] = "nosniff"
            response.headers["X-Frame-Options"] = "DENY"
            response.headers["Content-Security-Policy"] = "default-src 'self'"
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
            response.headers["Server"] = "Protected-API-Gateway"
            if "X-Powered-By" in response.headers:
                del response.headers["X-Powered-By"]

        else:
            # VULNERABLE: Overly permissive CORS and fingerprint leakage
            if origin:
                # Permissive origin reflection with credentials
                response.headers["Access-Control-Allow-Origin"] = origin
                response.headers["Access-Control-Allow-Credentials"] = "true"
            else:
                # Wildcard CORS
                response.headers["Access-Control-Allow-Origin"] = "*"

            response.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS"
            response.headers["Access-Control-Allow-Headers"] = "*"
            
            # Fingerprint disclosure
            response.headers["Server"] = "Werkzeug/3.1.9 Python/3.14.7"
            response.headers["X-Powered-By"] = "Flask-VAPT-API"
            # Deliberately missing X-Content-Type-Options, X-Frame-Options, CSP, HSTS

        return response

    @app.errorhandler(Exception)
    def handle_exception(e):
        """Handle unhandled errors with stack trace disclosure in vulnerable mode."""
        if Config.SECURE_MODE:
            return jsonify({
                "error": "Internal Server Error",
                "message": "An unexpected error occurred. Request ID logged."
            }), 500
        else:
            # Vulnerable mode leaks full stack trace, frame info, and exception type
            return jsonify({
                "error": "Internal Server Error",
                "exception_type": type(e).__name__,
                "exception_message": str(e),
                "traceback": traceback.format_exc().splitlines()
            }), 500

    return app

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="ShopVault REST API Testbed")
    parser.add_argument("--port", type=int, default=5000, help="Port to bind (default: 5000)")
    parser.add_argument("--secure", action="store_true", help="Run in hardened SECURE mode")
    parser.add_argument("--reseed", action="store_true", help="Re-seed SQLite database")
    args = parser.parse_args()

    if args.reseed:
        seed_database()

    app = create_app(secure_mode=args.secure)
    print(f"[*] Starting ShopVault REST API on http://127.0.0.1:{args.port} (Secure Mode: {args.secure})")
    app.run(host="127.0.0.1", port=args.port, debug=False, threaded=True)
