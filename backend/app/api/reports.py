from fastapi import APIRouter, HTTPException, Depends, Query
from fastapi.responses import HTMLResponse, JSONResponse
from app.review.findings import get_findings_by_project_id
from app.review.audit import get_audit_logs_for_project
from app.reports.generator import generate_html_report, generate_json_report
from app.core.auth import get_current_user, verify_project_access
import json


router = APIRouter()

@router.get("/{project_id}")
async def get_report(
    project_id: str,
    format: str = Query("html", description="Report format: 'html' or 'json'"),
    current_user: dict = Depends(get_current_user)
):
    """
    Returns a structured review report for a specific project.
    """
    verify_project_access(current_user, project_id)
    
    findings = get_findings_by_project_id(project_id)
    if not findings:
        raise HTTPException(status_code=404, detail="No findings found for this project.")
        
    audit_logs = get_audit_logs_for_project(project_id)
    
    if format.lower() == "json":
        json_content = generate_json_report(project_id, findings, audit_logs)
        return JSONResponse(content=json.loads(json_content))
    else:
        # Default to HTML
        html_content = generate_html_report(project_id, findings, audit_logs)
        return HTMLResponse(content=html_content)
