import sqlite3
import os
import json
import hashlib
import secrets

DB_PATH = os.path.join(os.path.dirname(__file__), "..", "..", "data", "users.db")

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def hash_password(password: str, salt: bytes = None) -> str:
    if salt is None:
        salt = secrets.token_bytes(16)
    key = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt,
        100000
    )
    return salt.hex() + ":" + key.hex()

def verify_password(plain_password: str, hashed_password: str) -> bool:
    try:
        salt_hex, key_hex = hashed_password.split(":")
        salt = bytes.fromhex(salt_hex)
        expected_key = hashlib.pbkdf2_hmac(
            'sha256',
            plain_password.encode('utf-8'),
            salt,
            100000
        ).hex()
        return secrets.compare_digest(key_hex, expected_key)
    except Exception:
        return False

def init_users_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL,
            projects TEXT NOT NULL
        )
    ''')
    conn.commit()
    
    # Only seed default dev users in development mode
    environment = os.getenv("ENVIRONMENT", "development")
    cursor.execute("SELECT COUNT(*) FROM users")
    user_count = cursor.fetchone()[0]
    
    if user_count == 0:
        if environment == "production":
            print("[WARNING] No users exist in the database. Create an admin user manually:")
            print("          python -c \"from app.core.security import create_user; create_user('admin', '<STRONG_PASSWORD>', 'ADMIN', ['*'])\"")
        else:
            print("[INFO] Seeding default dev users (admin, reviewer, dev). Do NOT use these in production!")
            create_user("admin", "admin123", "ADMIN", ["*"])
            create_user("reviewer", "review123", "REVIEWER", ["proj-1"])
            create_user("dev", "dev123", "DEVELOPER", ["proj-1", "proj-2"])
        
    conn.close()

def create_user(username, password, role, projects):
    conn = get_db()
    cursor = conn.cursor()
    pwd_hash = hash_password(password)
    cursor.execute(
        "INSERT OR REPLACE INTO users (username, password_hash, role, projects) VALUES (?, ?, ?, ?)",
        (username, pwd_hash, role, json.dumps(projects))
    )
    conn.commit()
    conn.close()

def get_user(username: str):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
    row = cursor.fetchone()
    conn.close()
    if row:
        user = dict(row)
        user["projects"] = json.loads(user["projects"])
        return user
    return None

init_users_db()
