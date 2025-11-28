import sqlite3
from datetime import datetime, timezone
from flask import g, current_app
from werkzeug.security import generate_password_hash, check_password_hash

def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(
            current_app.config["DATABASE"],
            detect_types=sqlite3.PARSE_DECLTYPES,
            check_same_thread=False,
        )
        g.db.row_factory = sqlite3.Row
    return g.db

def close_db(e=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()

def init_db():
    db = get_db()
    with current_app.open_resource("schema.sql") as f:
        db.executescript(f.read().decode("utf-8"))
    db.commit()

def create_user(username: str, password: str):
    db = get_db()
    db.execute(
        "INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?)",
        (username, generate_password_hash(password), datetime.now(timezone.utc).isoformat()),
    )
    db.commit()

def get_user_by_username(username: str):
    db = get_db()
    cur = db.execute("SELECT * FROM users WHERE username = ?", (username,))
    return cur.fetchone()

def verify_user(username: str, password: str) -> bool:
    row = get_user_by_username(username)
    if not row:
        return False
    return check_password_hash(row["password_hash"], password)
