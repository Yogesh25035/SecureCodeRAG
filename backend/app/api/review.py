from fastapi import APIRouter, HTTPException, Body, Depends
from typing import Dict, Any, List
from app.review.findings import update_finding_status, get_finding
from app.schemas.findings import FindingStatus
from app.review.audit import get_audit_logs
from app.core.auth import get_current_user, require_role, verify_project_access

router = APIRouter()

@router.post("/{finding_id}/accept")
async def accept_finding(
    finding_id: str, 
    current_user: dict = Depends(require_role(["REVIEWER", "ADMIN"]))
):
    finding = get_finding(finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
        
    verify_project_access(current_user, finding.get("repository"))
        
    update_finding_status(finding_id, FindingStatus.ACCEPTED, user=current_user["username"])
    return {"status": "success", "message": f"Finding {finding_id} accepted."}

@router.post("/{finding_id}/reject")
async def reject_finding(
    finding_id: str, 
    payload: Dict[str, Any] = Body(None),
    current_user: dict = Depends(require_role(["REVIEWER", "ADMIN"]))
):
    finding = get_finding(finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
        
    verify_project_access(current_user, finding.get("repository"))
        
    update_finding_status(finding_id, FindingStatus.REJECTED, edit_data=payload, user=current_user["username"])
    return {"status": "success", "message": f"Finding {finding_id} rejected."}

@router.post("/{finding_id}/edit")
async def edit_finding(
    finding_id: str, 
    payload: Dict[str, Any] = Body(...),
    current_user: dict = Depends(require_role(["REVIEWER", "ADMIN"]))
):
    finding = get_finding(finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
        
    verify_project_access(current_user, finding.get("repository"))
        
    payload.pop("finding_id", None)
    payload.pop("status", None)
    
    update_finding_status(finding_id, FindingStatus.EDITED, edit_data=payload, user=current_user["username"])
    return {"status": "success", "message": f"Finding {finding_id} edited and approved."}

@router.get("/system/audit")
async def fetch_audit_logs(
    limit: int = 100,
    current_user: dict = Depends(require_role(["REVIEWER", "ADMIN"]))
):
    # Depending on requirements, we can filter audit logs by the user's projects.
    # For MVP, just return them if they are REVIEWER/ADMIN (and further filtering could be done).
    logs = get_audit_logs(limit=limit)
    if current_user["role"] != "ADMIN" and "*" not in current_user["projects"]:
        logs = [log for log in logs if log["repository"] in current_user["projects"] or not log["repository"]]
    return logs

@router.get("/{finding_id}")
async def fetch_finding(
    finding_id: str,
    current_user: dict = Depends(get_current_user)
):
    finding = get_finding(finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    verify_project_access(current_user, finding.get("repository"))
    return finding
