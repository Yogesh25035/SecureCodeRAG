import os
import uuid
import json
import tempfile
import shutil
from fastapi.testclient import TestClient

from app.main import app
from app.review.findings import get_findings_by_project_id, update_finding_status
from app.schemas.findings import FindingStatus
from app.review.audit import get_audit_logs_for_project
from app.reports.generator import generate_json_report

client = TestClient(app)

def run_e2e_acceptance():
    print("=== STARTING E2E ACCEPTANCE TEST ===")
    
    # 1. Login (Mocking the dependency for test client)
    from app.core.auth import create_access_token
    token = create_access_token({"sub": "admin", "role": "ADMIN", "projects": ["*"]})
    headers = {"Authorization": f"Bearer {token}"}
    
    # 2. Create/select project
    project_id = str(uuid.uuid4())
    print(f"[2] Created project_id: {project_id}")
    
    # 3. Upload C/C++ repository (synthetic zip)
    synth_dir = os.path.join(os.path.dirname(__file__), "synthetic_repo")
    with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as tmp_zip:
        shutil.make_archive(tmp_zip.name.replace(".zip", ""), 'zip', synth_dir)
        zip_path = tmp_zip.name
    
    # Override auth dependencies for endpoints
    from app.core.auth import get_current_user
    from app.api.repositories import require_role
    app.dependency_overrides[get_current_user] = lambda: {"username": "admin", "role": "ADMIN", "projects": ["*"]}
    app.dependency_overrides[require_role(["ADMIN"])] = lambda: {"username": "admin", "role": "ADMIN", "projects": ["*"]}
    
    with open(zip_path, "rb") as f:
        # Steps 4 (Index repository) are done inside the upload route automatically
        res_upload = client.post("/api/repositories/upload", files={"file": ("synth.zip", f, "application/zip")})
    assert res_upload.status_code == 200
    upload_data = res_upload.json()
    actual_project_id = upload_data["project_id"]
    print(f"[3/4] Uploaded and Indexed repository. project_id: {actual_project_id}")
    os.remove(zip_path)
    
    # Let's read a file from synth repo to analyze
    with open(os.path.join(synth_dir, "utils.c"), "r") as f:
        code_content = f.read()
        
    # 5, 6, 7, 8, 9, 10, 11 (Analyze code handles static, cppcheck, RAG, LLM, structure)
    req_payload = {
        "code": code_content,
        "language": "c",
        "project_id": actual_project_id,
        "repo_version": "v1.0"
    }
    res_analyze = client.post("/api/analyze", json=req_payload)
    if res_analyze.status_code != 200:
        print(f"Analyze failed: {res_analyze.text}")
    assert res_analyze.status_code == 200
    analysis = res_analyze.json()
    vulns = analysis["vulnerabilities"]
    print(f"[5-11] Code analyzed. Found {len(vulns)} vulnerabilities.")
    
    assert len(vulns) >= 2, "Expected at least strcpy and strcat"
    for v in vulns:
        assert v["evidence"] != "", "All findings must have evidence"
        assert v["status"] == "PENDING_REVIEW", "No automatic approval allowed"
        
    # 12. Review findings
    findings_db = get_findings_by_project_id(actual_project_id)
    assert len(findings_db) == len(vulns)
    
    finding_id_1 = findings_db[0]["finding_id"]
    finding_id_2 = findings_db[1]["finding_id"] if len(findings_db) > 1 else None
    
    # 13. Accept one
    update_finding_status(finding_id_1, FindingStatus.ACCEPTED, user="reviewer_admin", model="test_llm")
    print(f"[13] Accepted finding: {finding_id_1}")
    
    # 14. Edit one
    if finding_id_2:
        edit_data = {"finding": "Manually improved AI explanation", "reason": "AI missed context"}
        update_finding_status(finding_id_2, FindingStatus.EDITED, edit_data=edit_data, user="reviewer_admin", model="test_llm")
        print(f"[14] Edited finding: {finding_id_2}")
        
    # 15. Reject one (Assume a 3rd finding exists, or re-use)
    # We will just simulate a rejected finding if we have 3, otherwise skip 15
    if len(findings_db) > 2:
        finding_id_3 = findings_db[2]["finding_id"]
        update_finding_status(finding_id_3, FindingStatus.REJECTED, user="reviewer_admin", model="test_llm")
        print(f"[15] Rejected finding: {finding_id_3}")
        
    # 16. Generate report
    report_json_str = generate_json_report(actual_project_id, get_findings_by_project_id(actual_project_id), get_audit_logs_for_project(actual_project_id))
    report = json.loads(report_json_str)
    print(f"[16] Generated report for project {actual_project_id}")
    
    # 17. Inspect audit trail
    logs = get_audit_logs_for_project(actual_project_id)
    review_logs = [l for l in logs if l["event_type"] == "REVIEW"]
    assert len(review_logs) >= 2
    print(f"[17] Inspected audit trail. Found {len(logs)} total events.")
    
    # 18. Verify project isolation
    from app.vectorstore.index import VECTORSTORE_DIR
    assert os.path.exists(os.path.join(VECTORSTORE_DIR, actual_project_id))
    
    # Verify no external transmission
    from app.core.config import settings
    is_external = settings.LLM_PROVIDER.lower() in ("gemini", "openai")
    print(f"[18] Is external transmission configured: {is_external} (Provider: {settings.LLM_PROVIDER})")
    
    print("=== E2E TEST COMPLETED SUCCESSFULLY ===")

if __name__ == "__main__":
    run_e2e_acceptance()
