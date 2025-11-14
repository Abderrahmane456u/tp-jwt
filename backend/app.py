from flask import Flask, request, jsonify
from flask_cors import CORS
import jwt
import datetime
import os
from dotenv import load_dotenv
import bcrypt

load_dotenv()
app = Flask(__name__)
CORS(app)

SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret")
ACCESS_TOKEN_EXPIRES_MIN = int(os.getenv("ACCESS_TOKEN_EXPIRES_MIN", 5))
REFRESH_TOKEN_EXPIRES_DAYS = int(os.getenv("REFRESH_TOKEN_EXPIRES_DAYS", 7))

# -----------------------
# Helper bcrypt
# -----------------------
def hash_pw(password):
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

# -----------------------
# Fake database
# -----------------------
USERS = {
    "admin": {
        "password": hash_pw("1234"),
        "role": "admin",
        "email": "admin@example.com",
        "permissions": ["read", "write"]
    },
    "user": {
        "password": hash_pw("pass"),
        "role": "user",
        "email": "user@example.com",
        "permissions": ["read"]
    }
}

# -----------------------
# Token creators
# -----------------------
def create_access_token(username, role, email, permissions):
    now = datetime.datetime.utcnow()
    payload = {
        "sub": username,
        "role": role,
        "email": email,
        "permissions": permissions,
        "iat": now,
        "exp": now + datetime.timedelta(minutes=ACCESS_TOKEN_EXPIRES_MIN),
        "type": "access"
    }
    return jwt.encode(payload, SECRET_KEY, algorithm="HS256")

def create_refresh_token(username):
    now = datetime.datetime.utcnow()
    payload = {
        "sub": username,
        "iat": now,
        "exp": now + datetime.timedelta(days=REFRESH_TOKEN_EXPIRES_DAYS),
        "type": "refresh"
    }
    return jwt.encode(payload, SECRET_KEY, algorithm="HS256")

# -----------------------
# Decode token with error handling
# -----------------------
def decode_token(token):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        return payload, None
    except jwt.ExpiredSignatureError:
        return None, ("expired", "Token expiré")
    except jwt.InvalidTokenError:
        return None, ("invalid", "Token invalide")

# -----------------------
# Middleware: require token
# -----------------------
def require_token(fn):
    from functools import wraps
    @wraps(fn)
    def wrapper(*args, **kwargs):
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return jsonify({"error": "Token manquant"}), 401

        token = auth.split(" ")[1]
        payload, err = decode_token(token)

        if err:
            return jsonify({"error": err[1]}), 401

        if payload.get("type") != "access":
            return jsonify({"error": "Token non autorisé"}), 401

        request.user = payload
        return fn(*args, **kwargs)
    return wrapper

# -----------------------
# Routes
# -----------------------

@app.route("/login", methods=["POST"])
def login():
    data = request.json or {}
    username = data.get("username")
    password = data.get("password")

    user = USERS.get(username)
    if not user:
        return jsonify({"error": "Identifiants invalides"}), 401

    if not bcrypt.checkpw(password.encode(), user["password"].encode()):
        return jsonify({"error": "Identifiants invalides"}), 401

    access = create_access_token(
        username,
        user["role"],
        user["email"],
        user["permissions"]
    )

    refresh = create_refresh_token(username)

    return jsonify({
        "access_token": access,
        "refresh_token": refresh,
        "user": username,
        "role": user["role"],
        "email": user["email"]
    })

# -----------------------
# Protected routes
# -----------------------

@app.route("/profile", methods=["GET"])
@require_token
def profile():
    return jsonify({
        "message": "Profil utilisateur",
        "user": request.user["sub"],
        "role": request.user["role"],
        "email": request.user["email"]
    })

@app.route("/me", methods=["GET"])
@require_token
def me():
    return jsonify(request.user)

@app.route("/admin", methods=["GET"])
@require_token
def admin():
    if request.user["role"] != "admin":
        return jsonify({"error": "Accès refusé"}), 403
    return jsonify({"message": "Bienvenue admin"})

@app.route("/can-write", methods=["GET"])
@require_token
def can_write():
    if "write" in request.user.get("permissions", []):
        return jsonify({"message": "Permission accordée (write)"}), 200
    return jsonify({"error": "Permission 'write' requise"}), 403

# -----------------------
# Public route
# -----------------------
@app.route("/public-info", methods=["GET"])
def public():
    return jsonify({"message": "Route publique accessible sans token."})

# -----------------------
# Refresh token
# -----------------------
@app.route("/refresh", methods=["POST"])
def refresh():
    data = request.json or {}
    token = data.get("refresh_token")

    payload, err = decode_token(token)
    if err:
        return jsonify({"error": err[1]}), 401

    if payload["type"] != "refresh":
        return jsonify({"error": "Token invalide"}), 401

    username = payload["sub"]
    user = USERS.get(username)

    new_access = create_access_token(
        username,
        user["role"],
        user["email"],
        user["permissions"]
    )

    return jsonify({"access_token": new_access})

# -----------------------
# Start
# -----------------------
@app.route("/")
def index():
    return jsonify({"status": "backend ready"})

if __name__ == "__main__":
    app.run(port=int(os.getenv("PORT", 5000)), debug=True)
