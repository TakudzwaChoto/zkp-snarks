import sqlite3
import os
from werkzeug.security import generate_password_hash


def init_db():
    conn = sqlite3.connect("llm_logs.db")
    cursor = conn.cursor()
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            user_id TEXT NOT NULL,
            prompt_encrypted TEXT NOT NULL,
            response_encrypted TEXT NOT NULL,
            previous_hash TEXT,
            current_hash TEXT NOT NULL,
            signature TEXT NOT NULL
        )
        """
    )
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL
        )
        """
    )
    conn.commit()
    conn.close()


def ensure_default_admin():
    username = os.getenv("ADMIN_USERNAME", "admin")
    password = os.getenv("ADMIN_PASSWORD", "adminpass")
    role = "admin"
    conn = sqlite3.connect("llm_logs.db")
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
    row = cursor.fetchone()
    if row is None:
        cursor.execute(
            "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
            (username, generate_password_hash(password), role),
        )
        conn.commit()
    conn.close()


def get_user(username: str):
    conn = sqlite3.connect("llm_logs.db")
    cursor = conn.cursor()
    cursor.execute("SELECT username, password_hash, role FROM users WHERE username = ?", (username,))
    row = cursor.fetchone()
    conn.close()
    if not row:
        return None
    return {"username": row[0], "password_hash": row[1], "role": row[2]}


init_db()
ensure_default_admin()