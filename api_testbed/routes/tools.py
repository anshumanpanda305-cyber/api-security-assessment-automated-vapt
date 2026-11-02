import subprocess
import re
import os
import sys
from flask import Blueprint, request, jsonify
from ..config import Config

tools_bp = Blueprint("tools", __name__, url_prefix="/api/v1/tools")

@tools_bp.route("/ping", methods=["GET"])
def network_ping():
    """
    Network diagnostics ping utility.
    VULNERABLE (OS Command Injection - CWE-78):
      - In vulnerable mode, executes ping command using shell=True with unescaped string formatting!
      - Attacker can pass: 127.0.0.1 & whoami OR 127.0.0.1 | echo VULN_CONFIRMED
    SECURE:
      - Validates host against strict hostname/IP regex and executes command as list with shell=False.
    """
    host = request.args.get("host", "").strip()
    if not host:
        return jsonify({"error": "Bad Request", "message": "Missing 'host' query parameter"}), 400

    if Config.SECURE_MODE:
        # Strict alphanumeric + dot + hyphen validation
        if not re.match(r"^[a-zA-Z0-9.-]+$", host):
            return jsonify({
                "error": "Bad Request",
                "message": "Invalid host parameter. Only alphanumeric characters, dots, and hyphens allowed."
            }), 400

        try:
            # Safe list invocation, no shell interpretation
            cmd = ["ping", "-n", "1", host] if sys.platform == "win32" else ["ping", "-c", "1", host]
            proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=5)
            return jsonify({
                "status": "success",
                "target": host,
                "output": proc.stdout
            }), 200
        except Exception as e:
            return jsonify({"error": "Internal Error", "message": "Ping execution failed"}), 500

    else:
        # VULNERABLE: Direct string interpolation with shell=True
        try:
            ping_flag = "-n 1" if sys.platform == "win32" else "-c 1"
            cmd_str = f"ping {ping_flag} {host}"
            raw_output = subprocess.check_output(cmd_str, shell=True, stderr=subprocess.STDOUT, text=True, timeout=5)
            return jsonify({
                "status": "success",
                "target": host,
                "command_executed": cmd_str,
                "output": raw_output
            }), 200
        except subprocess.CalledProcessError as e:
            return jsonify({
                "status": "failed",
                "exit_code": e.returncode,
                "output": e.output
            }), 500
        except Exception as e:
            return jsonify({"error": "Execution Error", "details": str(e)}), 500

@tools_bp.route("/debug/crash", methods=["GET"])
def trigger_crash():
    """Endpoint designed to inspect error handling and stack trace disclosure."""
    if Config.SECURE_MODE:
        return jsonify({"error": "Not Found", "message": "Endpoint disabled in production"}), 404
    # Vulnerable mode: triggers unhandled exception that bubbles up to Flask debugger
    raise RuntimeError("VAPT_SIMULATED_CRASH: Unhandled exception leaking internal call stack and environment vars.")

@tools_bp.route("/debug/config", methods=["GET"])
def debug_config():
    """Security Misconfiguration: Debug config exposure."""
    if Config.SECURE_MODE:
        return jsonify({"error": "Not Found", "message": "Endpoint not found"}), 404

    return jsonify({
        "debug_status": "ENABLED",
        "app_secret": Config.SECRET_KEY,
        "jwt_secret": Config.VULN_JWT_SECRET,
        "database_path": Config.DATABASE_PATH,
        "environment_variables": {k: v for k, v in os.environ.items() if "KEY" in k or "PASS" in k or "PATH" in k}
    }), 200
