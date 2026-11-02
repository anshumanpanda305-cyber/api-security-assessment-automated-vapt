import time
import datetime
import jwt
from flask import Blueprint, request, jsonify, g
from ..config import Config
from ..database import get_db_connection, hash_password

auth_bp = Blueprint("auth", __name__, url_prefix="/api/v1/auth")

# In-memory rate limiting tracker for login attempts (IP -> list of timestamps)
_login_attempts = {}

def get_token_from_header():
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        return None
    return auth_header.split(" ")[1].strip()

def decode_token(token: str):
    """
    Decodes and validates a JWT token according to current SECURE_MODE.
    VULNERABLE MODE:
      - Accepts 'alg': 'none' with empty/unverified signature.
      - Uses weak HMAC secret 'secret123'.
      - Ignores expiration 'exp'.
    SECURE MODE:
      - Strictly requires HS256 algorithm.
      - Validates signature with strong secret.
      - Enforces expiration.
    """
    if Config.SECURE_MODE:
        try:
            payload = jwt.decode(
                token,
                Config.get_jwt_secret(),
                algorithms=["HS256"],
                options={"verify_signature": True, "verify_exp": True}
            )
            return payload
        except Exception as e:
            return None
    else:
        # VULNERABLE MODE
        try:
            # Check unverified header to see if attacker used 'none' algorithm
            unverified_header = jwt.get_unverified_header(token)
            alg = unverified_header.get("alg", "").lower()

            if alg == "none":
                # Vulnerability: Accepts 'alg': 'none' without verifying cryptographic signature!
                payload = jwt.decode(
                    token,
                    options={"verify_signature": False, "verify_exp": False}
                )
                return payload

            # Otherwise verify with weak secret, but ignore expiration
            payload = jwt.decode(
                token,
                Config.VULN_JWT_SECRET,
                algorithms=["HS256"],
                options={"verify_signature": True, "verify_exp": False}
            )
            return payload
        except Exception:
            return None

def require_auth(f):
    """Decorator to enforce authentication on endpoints."""
    def wrapper(*args, **kwargs):
        token = get_token_from_header()
        if not token:
            return jsonify({
                "error": "Unauthorized",
                "message": "Missing Authorization Bearer token header"
            }), 401

        payload = decode_token(token)
        if not payload:
            return jsonify({
                "error": "Unauthorized",
                "message": "Invalid, tampered, or expired JWT token"
            }), 401

        # Attach authenticated user identity to Flask request context
        g.current_user = payload
        return f(*args, **kwargs)

    wrapper.__name__ = f.__name__
    return wrapper

@auth_bp.route("/login", methods=["POST"])
def login():
    """
    User login endpoint.
    VULNERABLE: No rate limiting, signs JWT with weak secret 'secret123'.
    SECURE: Rate limiting applied (429), signs with 256-bit secure secret.
    """
    client_ip = request.remote_addr or "127.0.0.1"

    # Rate limiting check in SECURE mode
    if Config.SECURE_MODE:
        now = time.time()
        attempts = _login_attempts.get(client_ip, [])
        # Keep attempts within last 60 seconds
        attempts = [t for t in attempts if now - t < 60]
        _login_attempts[client_ip] = attempts

        if len(attempts) >= 5:
            return jsonify({
                "error": "Too Many Requests",
                "message": "Rate limit exceeded. Maximum 5 login attempts per minute."
            }), 429

    data = request.get_json(silent=True) or {}
    username = data.get("username", "").strip()
    password = data.get("password", "")

    if not username or not password:
        return jsonify({"error": "Bad Request", "message": "Username and password required"}), 400

    conn = get_db_connection()
    user = conn.execute(
        "SELECT * FROM users WHERE username = ?", (username,)
    ).fetchone()
    conn.close()

    hashed = hash_password(password)
    if not user or user["password_hash"] != hashed:
        if Config.SECURE_MODE:
            _login_attempts.setdefault(client_ip, []).append(time.time())
        return jsonify({"error": "Unauthorized", "message": "Invalid username or password"}), 401

    # Issue JWT token
    exp_time = datetime.datetime.utcnow() + datetime.timedelta(hours=2)
    payload = {
        "sub": str(user["id"]),
        "user_id": user["id"],
        "username": user["username"],
        "email": user["email"],
        "role": user["role"],
        "is_admin": bool(user["is_admin"]),
        "exp": exp_time.timestamp()
    }

    secret = Config.get_jwt_secret()
    token = jwt.encode(payload, secret, algorithm="HS256")

    # In vulnerable mode, reset attempts on success
    return jsonify({
        "status": "success",
        "message": "Authentication successful",
        "access_token": token,
        "token_type": "Bearer",
        "user": {
            "id": user["id"],
            "username": user["username"],
            "role": user["role"],
            "is_admin": bool(user["is_admin"])
        }
    }), 200

@auth_bp.route("/register", methods=["POST"])
def register():
    """
    User registration endpoint.
    VULNERABLE: Mass Assignment during registration (allows setting role='admin').
    SECURE: Sanitizes role to 'user' and is_admin to 0.
    """
    data = request.get_json(silent=True) or {}
    username = data.get("username", "").strip()
    email = data.get("email", "").strip()
    password = data.get("password", "")

    if not username or not email or not password:
        return jsonify({"error": "Bad Request", "message": "Missing required fields"}), 400

    conn = get_db_connection()
    existing = conn.execute(
        "SELECT id FROM users WHERE username = ? OR email = ?", (username, email)
    ).fetchone()
    if existing:
        conn.close()
        return jsonify({"error": "Conflict", "message": "User already exists"}), 409

    if Config.SECURE_MODE:
        # SECURE: Ignore client-supplied privilege fields
        role = "user"
        is_admin = 0
    else:
        # VULNERABLE: Trust client-supplied privilege fields (Mass Assignment)
        role = data.get("role", "user")
        is_admin = 1 if data.get("is_admin") in (True, 1, "1", "true") else 0

    conn.execute(
        "INSERT INTO users (username, email, password_hash, role, is_admin) VALUES (?, ?, ?, ?, ?)",
        (username, email, hash_password(password), role, is_admin)
    )
    conn.commit()
    new_user = conn.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
    conn.close()

    return jsonify({
        "status": "success",
        "message": "User registered successfully",
        "user_id": new_user["id"],
        "assigned_role": role,
        "is_admin": bool(is_admin)
    }), 201
