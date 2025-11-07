import os, datetime, jwt
from flask import Flask, request, jsonify
from flask_cors import CORS
from functools import wraps

# Charger le fichier .env

app = Flask(__name__)
CORS(app)

SECRET_KEY = os.getenv("SECRET_KEY", "secret123")
ACCESS_TOKEN_EXPIRES_MIN = int(os.getenv("ACCESS_TOKEN_EXPIRES_MIN", "30"))

# --- Comptes de test ---
USERS = {
    "admin": {"password": "1234", "role": "admin"},
    "user": {"password": "pass", "role": "user"}
}

# --- Fonction pour créer un JWT ---
def create_token(username, role):
    payload = {
        "sub": username,
        "role": role,
        "iat": datetime.datetime.utcnow(),
        "exp": datetime.datetime.utcnow() + datetime.timedelta(minutes=ACCESS_TOKEN_EXPIRES_MIN)
    }
    return jwt.encode(payload, SECRET_KEY, algorithm="HS256")

# --- Décorateur de vérification du token ---
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if "Authorization" in request.headers:
            token = request.headers["Authorization"].split(" ")[1]
        if not token:
            return jsonify({"msg": "Token manquant"}), 401
        try:
            data = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
            request.user = data
        except jwt.ExpiredSignatureError:
            return jsonify({"msg": "Token expiré"}), 401
        except Exception:
            return jsonify({"msg": "Token invalide"}), 401
        return f(*args, **kwargs)
    return decorated

# --- Route login ---
@app.route("/login", methods=["POST"])
def login():
    creds = request.get_json()
    username = creds.get("username")
    password = creds.get("password")
    user = USERS.get(username)
    if not user or user["password"] != password:
        return jsonify({"msg": "Identifiants invalides"}), 401
    token = create_token(username, user["role"])
    return jsonify({"token": token})

# --- Route protégée /profile ---
@app.route("/profile", methods=["GET"])
@token_required
def profile():
    user = request.user
    return jsonify({
        "msg": f"Bienvenue {user['sub']}!",
        "role": user["role"]
    })

# --- Route /me : afficher le contenu du JWT ---
@app.route("/me", methods=["GET"])
@token_required
def me():
    return jsonify(request.user)

# --- Route /admin : réservée aux admins ---
@app.route("/admin", methods=["GET"])
@token_required
def admin_zone():
    if request.user["role"] != "admin":
        return jsonify({"msg": "Accès refusé"}), 403
    return jsonify({"msg": "Bienvenue dans la zone admin !"})

# --- Route /refresh : regénère un nouveau token ---
@app.route("/refresh", methods=["POST"])
@token_required
def refresh():
    old_user = request.user
    new_token = create_token(old_user["sub"], old_user["role"])
    return jsonify({"token": new_token})

# --- Démarrage du serveur ---
if __name__ == "__main__":
    port = int(os.getenv("PORT", "5000"))
    app.run("127.0.0.1",debug=True, port=port)
