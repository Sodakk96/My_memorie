import hashlib
import os
import re
import secrets
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path

from flask import Flask, jsonify, request, send_from_directory
from werkzeug.security import check_password_hash, generate_password_hash

BASE_DIR = Path(__file__).resolve().parent
INSTANCE_DIR = BASE_DIR / "instance"
DB_PATH = INSTANCE_DIR / "memoria_gata.sqlite3"
SESSION_DAYS = 7

app = Flask(__name__)
app.config.update(
    JSON_SORT_KEYS=False,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
)


@contextmanager
def get_db():
    INSTANCE_DIR.mkdir(exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db():
    with get_db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT NOT NULL UNIQUE COLLATE NOCASE,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS auth_sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                token_hash TEXT NOT NULL UNIQUE,
                expires_at TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_sessions_token ON auth_sessions(token_hash)")


def now_utc():
    return datetime.now(timezone.utc)


def token_digest(token):
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def current_user():
    token = request.cookies.get("gata_session")
    if not token:
        return None
    digest = token_digest(token)
    with get_db() as conn:
        row = conn.execute("""
            SELECT users.id, users.name, users.email, auth_sessions.expires_at
            FROM auth_sessions
            JOIN users ON users.id = auth_sessions.user_id
            WHERE auth_sessions.token_hash = ?
        """, (digest,)).fetchone()
        if not row:
            return None
        if datetime.fromisoformat(row["expires_at"]) <= now_utc():
            conn.execute("DELETE FROM auth_sessions WHERE token_hash = ?", (digest,))
            return None
        return {"id": row["id"], "name": row["name"], "email": row["email"]}


def create_session(user_id):
    raw_token = secrets.token_urlsafe(36)
    created = now_utc()
    expires = created + timedelta(days=SESSION_DAYS)
    with get_db() as conn:
        conn.execute("DELETE FROM auth_sessions WHERE expires_at <= ?", (created.isoformat(),))
        conn.execute(
            "INSERT INTO auth_sessions (user_id, token_hash, expires_at, created_at) VALUES (?, ?, ?, ?)",
            (user_id, token_digest(raw_token), expires.isoformat(), created.isoformat()),
        )
    return raw_token, expires


@app.get("/")
def home():
    return send_from_directory(BASE_DIR, "index.html")


@app.get("/api/health")
def health():
    return jsonify({"status": "ok", "service": "Memória Gata API"})


@app.post("/api/register")
def register():
    data = request.get_json(silent=True) or {}
    name = str(data.get("name", "")).strip()
    email = str(data.get("email", "")).strip().lower()
    password = str(data.get("password", ""))

    if len(name) < 2 or len(name) > 60:
        return jsonify({"error": "O nome deve ter entre 2 e 60 caracteres."}), 400
    if len(email) > 254 or not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email):
        return jsonify({"error": "Informe um e-mail válido."}), 400
    if len(password) < 8 or len(password) > 128:
        return jsonify({"error": "A senha deve ter entre 8 e 128 caracteres."}), 400

    password_hash = generate_password_hash(password, method="scrypt")
    try:
        with get_db() as conn:
            cursor = conn.execute(
                "INSERT INTO users (name, email, password_hash, created_at) VALUES (?, ?, ?, ?)",
                (name, email, password_hash, now_utc().isoformat()),
            )
            user_id = cursor.lastrowid
    except sqlite3.IntegrityError:
        return jsonify({"error": "Este e-mail já está cadastrado."}), 409

    token, expires = create_session(user_id)
    response = jsonify({"user": {"id": user_id, "name": name, "email": email}})
    response.set_cookie(
        "gata_session", token, httponly=True, samesite="Lax",
        expires=expires, path="/"
    )
    return response, 201


@app.post("/api/login")
def login():
    data = request.get_json(silent=True) or {}
    email = str(data.get("email", "")).strip().lower()
    password = str(data.get("password", ""))
    with get_db() as conn:
        user = conn.execute(
            "SELECT id, name, email, password_hash FROM users WHERE email = ?",
            (email,),
        ).fetchone()
    if not user or not check_password_hash(user["password_hash"], password):
        return jsonify({"error": "E-mail ou senha incorretos."}), 401

    token, expires = create_session(user["id"])
    response = jsonify({"user": {"id": user["id"], "name": user["name"], "email": user["email"]}})
    response.set_cookie(
        "gata_session", token, httponly=True, samesite="Lax",
        expires=expires, path="/"
    )
    return response


@app.get("/api/me")
def me():
    user = current_user()
    if not user:
        return jsonify({"user": None}), 200
    return jsonify({"user": user})


@app.post("/api/logout")
def logout():
    token = request.cookies.get("gata_session")
    if token:
        with get_db() as conn:
            conn.execute("DELETE FROM auth_sessions WHERE token_hash = ?", (token_digest(token),))
    response = jsonify({"message": "Você saiu da sua conta."})
    response.delete_cookie("gata_session", path="/", httponly=True, samesite="Lax")
    return response


if __name__ == "__main__":
    init_db()
    print("\n🐾 Memória Gata backend iniciado!")
    print("Abra: http://127.0.0.1:5000\n")
    app.run(host="127.0.0.1", port=5000, debug=True)
