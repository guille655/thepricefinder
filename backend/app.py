# backend/app.py
import os
from datetime import datetime, timedelta
import jwt

from flask import Flask, request, jsonify
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from models import Base, User

# ===== CONFIG =====
SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret")  # cámbialo en producción

# Lee orígenes permitidos desde variable de entorno (coma-separados)
# Ej: "https://TU-USUARIO.github.io,http://127.0.0.1:5500"
ALLOW_ORIGINS = os.getenv(
    "ALLOW_ORIGINS",
    "http://127.0.0.1:5500,http://localhost:5500"  # por defecto, desarrollo local
).split(",")

app = Flask(__name__)
CORS(app, resources={r"/api/*": {"origins": ALLOW_ORIGINS}})

print("[CORS] ALLOW_ORIGINS:", ALLOW_ORIGINS)  # ayuda para depurar

# DB SQLite local (archivo en backend/db.sqlite3)
DB_PATH = os.path.join(os.path.dirname(__file__), "db.sqlite3")
engine = create_engine(f"sqlite:///{DB_PATH}", echo=False)
Base.metadata.create_all(engine)
SessionLocal = sessionmaker(bind=engine)

# ===== JWT helpers =====
def create_token(email: str) -> str:
    payload = {
        "sub": email,
        "iat": datetime.utcnow(),
        "exp": datetime.utcnow() + timedelta(days=7)  # token válido 7 días
    }
    return jwt.encode(payload, SECRET_KEY, algorithm="HS256")

def decode_token(token: str):
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

def get_auth_email():
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return None
    token = auth.split(" ", 1)[1].strip()
    data = decode_token(token)
    if not data:
        return None
    return data.get("sub")

# ===== RUTAS =====
@app.get("/api/health")
def health():
    return {"status": "ok"}

@app.post("/api/signup")
def signup():
    data = request.get_json(silent=True) or {}
    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""

    if not email or "@" not in email:
        return jsonify({"ok": False, "error": "Email inválido"}), 400
    if len(password) < 8:
        return jsonify({"ok": False, "error": "La contraseña debe tener al menos 8 caracteres"}), 400

    with SessionLocal() as db:
        exists = db.execute(select(User).where(User.email == email)).scalar_one_or_none()
        if exists:
            return jsonify({"ok": False, "error": "Ese email ya está registrado"}), 409

        user = User(email=email, password_hash=generate_password_hash(password))
        db.add(user)
        db.commit()

    return jsonify({"ok": True, "message": "Registro correcto"}), 201

@app.post("/api/login")
def login():
    data = request.get_json(silent=True) or {}
    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""

    if not email or not password:
        return jsonify({"ok": False, "error": "Faltan credenciales"}), 400

    with SessionLocal() as db:
        user = db.execute(select(User).where(User.email == email)).scalar_one_or_none()
        if not user or not check_password_hash(user.password_hash, password):
            return jsonify({"ok": False, "error": "Credenciales inválidas"}), 401

    token = create_token(email)
    return jsonify({"ok": True, "message": "Login correcto", "token": token}), 200

@app.get("/api/me")
def me():
    email = get_auth_email()
    if not email:
        return jsonify({"ok": False, "error": "No autorizado"}), 401
    return jsonify({"ok": True, "email": email})
    
if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
