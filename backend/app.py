# app.py
from flask import Flask, request, jsonify
from flask_cors import CORS
import jwt
import datetime
import os
import bcrypt


app = Flask(__name__)
CORS(app)

SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret")
ACCESS_TOKEN_EXPIRES_MIN = int(os.getenv("ACCESS_TOKEN_EXPIRES_MIN", 5))
REFRESH_TOKEN_EXPIRES_DAYS = int(os.getenv("REFRESH_TOKEN_EXPIRES_DAYS", 7))

# ---------- Fake DB (hashed passwords) ----------
# For a real app, utilisez une vraie base de données.
def hash_pw(plain):
    return bcrypt.hashpw(plain.encode(), bcrypt.gensalt()).decode()

USERS = {
    "admin": {"password": hash_pw("1234"), "role": "admin"},
    "user":  {"password": hash_pw("pass"), "role": "user"}
}

# ---------- Tokens ----------
def create_access_token(username, role):
    now = datetime.datetime.utcnow()
    payload = {
        "sub": username,
        "role": role,
        "iat": now,
        "exp": now + datetime.timedelta(minutes=ACCESS_TOKEN_EXPIRES_MIN),
        "type": "access"
    }
    token = jwt.encode(payload, SECRET_KEY, algorithm="HS256")
    # PyJWT returns str in newer versions; ensure str
    return token

def create_refresh_token(username):
    now = datetime.datetime.utcnow()
    payload = {
        "sub": username,
        "iat": now,
        "exp": now + datetime.timedelta(days=REFRESH_TOKEN_EXPIRES_DAYS),
        "type": "refresh"
    }
    token = jwt.encode(payload, SECRET_KEY, algorithm="HS256")
    return token

# ---------- Helpers ----------
def decode_token(token):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        return payload, None
    except jwt.ExpiredSignatureError:
        return None, ("expired", "Token expiré")
    except jwt.InvalidTokenError:
        return None, ("invalid", "Token invalide")

def require_token(fn):
    from functools import wraps
    @wraps(fn)
    def wrapper(*args, **kwargs):
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return jsonify({"error": "Token manquant"}), 401
        token = auth.split(" ", 1)[1]
        payload, err = decode_token(token)
        if err:
            # err is tuple like ("expired","Token expiré")
            code, msg = err
            return jsonify({"error": msg}), 401
        # attach user info to request
        request.user = payload
        # ensure it's an access token
        if payload.get("type") != "access":
            return jsonify({"error": "Token non autorisé"}), 401
        return fn(*args, **kwargs)
    return wrapper

# ---------- Routes ----------
@app.route("/login", methods=["POST"])
def login():
    data = request.json or {}
    username = data.get("username")
    password = data.get("password")
    if not username or not password:
        return jsonify({"error": "username et password requis"}), 400

    user = USERS.get(username)
    if not user:
        return jsonify({"error": "Identifiants invalides"}), 401

    # check bcrypt
    if not bcrypt.checkpw(password.encode(), user["password"].encode()):
        return jsonify({"error": "Identifiants invalides"}), 401

    access_token = create_access_token(username, user["role"])
    refresh_token = create_refresh_token(username)

    return jsonify({
        "access_token": access_token,
        "refresh_token": refresh_token,
        "user": username,
        "role": user["role"]
    })


@app.route("/profile", methods=["GET"])
@require_token
def profile():
    return jsonify({
        "message": "Profil utilisateur",
        "user": request.user.get("sub"),
        "role": request.user.get("role")
    })


@app.route("/me", methods=["GET"])
@require_token
def me():
    # retourne le payload JWT (sub, role, iat, exp, type ...)
    return jsonify(request.user)


@app.route("/admin", methods=["GET"])
@require_token
def admin_route():
    if request.user.get("role") != "admin":
        return jsonify({"error": "Accès refusé – Admin uniquement"}), 403
    return jsonify({
        "message": "Bienvenue admin",
        "user": request.user.get("sub")
    })


@app.route("/refresh", methods=["POST"])
def refresh():
    data = request.json or {}
    refresh_token = data.get("refresh_token")
    if not refresh_token:
        return jsonify({"error": "refresh_token requis"}), 400

    payload, err = decode_token(refresh_token)
    if err:
        code, msg = err
        return jsonify({"error": msg}), 401

    # ensure token is refresh type
    if payload.get("type") != "refresh":
        return jsonify({"error": "Token invalide"}), 401

    username = payload.get("sub")
    user = USERS.get(username)
    if not user:
        return jsonify({"error": "Utilisateur introuvable"}), 401

    new_access = create_access_token(username, user["role"])
    return jsonify({"access_token": new_access})


# health
@app.route("/", methods=["GET"])
def index():
    return jsonify({"ok": True, "message": "Backend JWT ready"})

if __name__ == "__main__":
    port = int(os.getenv("PORT", 5000))
    app.run(debug=True, port=port)