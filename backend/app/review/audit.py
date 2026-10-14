import sqlite3
import os
import json
from datetime import datetime

DB_PATH = os.path.join(os.path.dirname(__file__), "..", "..", "data", "review.db")

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_audit_db():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("DROP TABLE IF EXISTS audit_log")
    cursor.execute('''
        CREATE TABLE audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_type TEXT,
            timestamp TEXT,
            user TEXT,
            project_id TEXT,
            repo_version TEXT,
            file TEXT,
            line INTEGER,
            finding_id TEXT,
            detection_source TEXT,
            model_name TEXT,
            model_version TEXT,
            rag_sources TEXT,
            ai_explanation TEXT,
            recommendation TEXT,
            confidence REAL,
            review_status TEXT,
            reviewer_changes TEXT,
            reason TEXT
        )
    ''')
    conn.commit()
    conn.close()

def log_audit_event(
    event_type: str, finding_id: str,
    user: str = "system", project_id: str = "", repo_version: str = "",
    file: str = "", line: int = 0, detection_source: str = "",
    model_name: str = "", model_version: str = "", rag_sources: str = "",
    ai_explanation: str = "", recommendation: str = "", confidence: float = 0.0,
    review_status: str = "", reviewer_changes: str = "", reason: str = ""
):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO audit_log (
            event_type, timestamp, user, project_id, repo_version, file, line,
            finding_id, detection_source, model_name, model_version, rag_sources,
            ai_explanation, recommendation, confidence, review_status, reviewer_changes, reason
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        event_type, datetime.utcnow().isoformat(), user, project_id, repo_version, file, line,
        finding_id, detection_source, model_name, model_version, rag_sources,
        ai_explanation, recommendation, confidence, review_status, reviewer_changes, reason
    ))
    conn.commit()
    conn.close()

def get_audit_logs(limit: int = 100):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM audit_log ORDER BY timestamp DESC LIMIT ?', (limit,))
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]

def get_audit_logs_for_project(project_id: str) -> list:
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM audit_log WHERE project_id = ? ORDER BY timestamp DESC', (project_id,))
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]

init_audit_db()
