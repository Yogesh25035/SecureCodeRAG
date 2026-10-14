import sqlite3
import os
import json
from ..schemas.findings import StructuredFinding, FindingStatus
from .audit import log_audit_event

DB_PATH = os.path.join(os.path.dirname(__file__), "..", "..", "data", "review.db")


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS findings (
            finding_id TEXT PRIMARY KEY,
            project_id TEXT,
            file TEXT,
            function TEXT,
            line_start INTEGER,
            line_end INTEGER,
            severity TEXT,
            category TEXT,
            title TEXT,
            finding TEXT,
            evidence TEXT,
            root_cause TEXT,
            rule TEXT,
            source TEXT,
            confidence REAL,
            diagnostic_message TEXT,
            evidence_status TEXT DEFAULT 'INSUFFICIENT_CONTEXT',
            recommendation TEXT,
            suggested_fix TEXT,
            status TEXT
        )
    """)
    columns = {row[1] for row in cursor.execute("PRAGMA table_info(findings)")}
    if "evidence_status" not in columns:
        cursor.execute(
            "ALTER TABLE findings ADD COLUMN evidence_status TEXT DEFAULT 'INSUFFICIENT_CONTEXT'"
        )
    if "diagnostic_message" not in columns:
        cursor.execute("ALTER TABLE findings ADD COLUMN diagnostic_message TEXT")
    conn.commit()
    conn.close()


def save_finding(finding: StructuredFinding):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        """
        INSERT OR REPLACE INTO findings (
            finding_id, project_id, file, function, line_start, line_end,
            severity, category, title, finding, evidence, root_cause,
            rule, source, confidence, diagnostic_message, evidence_status,
            recommendation, suggested_fix, status
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """,
        (
            finding.finding_id,
            finding.project_id,
            finding.file,
            finding.function,
            finding.line_start,
            finding.line_end,
            finding.severity,
            finding.category,
            finding.title,
            finding.finding,
            finding.evidence,
            finding.root_cause,
            finding.rule,
            finding.source,
            finding.confidence,
            finding.diagnostic_message,
            finding.evidence_status,
            finding.recommendation,
            finding.suggested_fix,
            finding.status,
        ),
    )
    conn.commit()
    conn.close()


def get_finding(finding_id: str) -> dict:
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM findings WHERE finding_id = ?", (finding_id,))
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None


def get_findings_by_project_id(project_id: str) -> list:
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM findings WHERE project_id = ?", (project_id,))
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]


def update_finding_status(
    finding_id: str,
    new_status: FindingStatus,
    edit_data: dict = None,
    user: str = "local_user",
    model: str = "configured_llm",
):
    conn = get_db()
    cursor = conn.cursor()

    # Get current finding for audit
    cursor.execute("SELECT * FROM findings WHERE finding_id = ?", (finding_id,))
    row = cursor.fetchone()
    if not row:
        conn.close()
        return

    old_finding = dict(row)

    if edit_data and new_status == FindingStatus.EDITED:
        # Filter valid keys for findings table
        valid_keys = [
            "title",
            "severity",
            "category",
            "finding",
            "recommendation",
            "suggested_fix",
        ]
        update_data = {k: v for k, v in edit_data.items() if k in valid_keys}

        if update_data:
            set_clause = ", ".join([f"{k} = ?" for k in update_data.keys()])
            values = list(update_data.values()) + [new_status.value, finding_id]
            cursor.execute(
                f"""
                UPDATE findings 
                SET {set_clause}, status = ? 
                WHERE finding_id = ?
            """,
                values,
            )
        else:
            cursor.execute(
                "UPDATE findings SET status = ? WHERE finding_id = ?",
                (new_status.value, finding_id),
            )
    else:
        cursor.execute(
            """
            UPDATE findings 
            SET status = ? 
            WHERE finding_id = ?
        """,
            (new_status.value, finding_id),
        )

    conn.commit()
    conn.close()

    # Write to audit log
    action_str = str(new_status.value)
    reason = (
        edit_data.get("reason", edit_data.get("review_reason", "")) if edit_data else ""
    )

    log_audit_event(
        event_type="REVIEW",
        finding_id=finding_id,
        user=user,
        project_id=old_finding.get("project_id", "unknown"),
        repo_version="",  # Can be expanded later
        file=old_finding.get("file", "unknown"),
        line=old_finding.get("line_start", 0),
        detection_source=old_finding.get("source", "unknown"),
        model_name=model,
        ai_explanation=old_finding.get("finding", ""),
        review_status=action_str,
        reviewer_changes=json.dumps(edit_data) if edit_data else "",
        reason=reason,
    )


# Initialize DB on load
init_db()
