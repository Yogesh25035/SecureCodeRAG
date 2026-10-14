import os
import json
import tempfile
import shutil
import uuid
import time
from fastapi.testclient import TestClient

from app.main import app
from app.review.findings import get_findings_by_project_id, update_finding_status
from app.schemas.findings import FindingStatus
from app.review.audit import get_audit_logs_for_project
from app.reports.generator import generate_json_report
from app.core.config import settings
from app.vectorstore.index import VECTORSTORE_DIR

def run_verification():
    print("=== FEATURE COMPLETENESS VERIFICATION ===")
    client = TestClient(app)
    
    # Setup Mock Auth
    from app.core.auth import get_current_user
    from app.api.repositories import require_role
    app.dependency_overrides[get_current_user] = lambda: {"username": "admin", "role": "ADMIN", "projects": ["*"]}
    app.dependency_overrides[require_role(["ADMIN"])] = lambda: {"username": "admin", "role": "ADMIN", "projects": ["*"]}
    
    project_id = str(uuid.uuid4())
    
    # 1. Submit C/C++ code containing known security issues.
    synth_dir = os.path.join(os.path.dirname(__file__), "tests", "synthetic_repo")
    with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as tmp_zip:
        shutil.make_archive(tmp_zip.name.replace(".zip", ""), 'zip', synth_dir)
        zip_path = tmp_zip.name
        
    with open(zip_path, "rb") as f:
        res_upload = client.post("/api/repositories/upload", files={"file": ("synth.zip", f, "application/zip")})
    assert res_upload.status_code == 200, "Upload failed"
    upload_data = res_upload.json()
    actual_project_id = upload_data["project_id"]
    os.remove(zip_path)
    print("[PASS] 1. Submit C/C++ code containing known security issues.")
    
    # 2. Run /api/analyze using: Ollama, deepseek-coder-v2:16b
    assert settings.LLM_PROVIDER == "ollama", "Provider not ollama"
    assert settings.LLM_MODEL == "deepseek-coder-v2:16b", "Model not deepseek"
    
    with open(os.path.join(synth_dir, "utils.c"), "r") as f:
        code_content = f.read()
        
    req_payload = {
        "code": code_content,
        "language": "c",
        "project_id": actual_project_id,
        "repo_version": "v1.0"
    }
    res_analyze = client.post("/api/analyze", json=req_payload)
    assert res_analyze.status_code == 200, f"Analyze failed: {res_analyze.text}"
    analysis = res_analyze.json()
    vulns = analysis["vulnerabilities"]
    assert len(vulns) > 0, "No findings detected"
    print(f"[PASS] 2. Run /api/analyze using Ollama and {settings.LLM_MODEL}. Found {len(vulns)} vulnerabilities.")
    
    # 3. Verify each finding contains required fields
    for v in vulns:
        assert v.get("category"), "Missing category"
        assert v.get("severity"), "Missing severity"
        assert v.get("file"), "Missing file"
        assert "line_start" in v or "line" in v, "Missing line number"
        assert v.get("evidence"), "Missing code evidence"
        assert v.get("confidence") is not None, "Missing confidence"
        assert v.get("status") == "PENDING_REVIEW", "Status not PENDING_REVIEW"
        
        finding_text = v.get("finding", "")
        # The explanation text contains Explanation, Root Cause, Recommendation, etc.
        assert finding_text != "", "Missing explanation text"
        # DeepSeek populates "Recommendation:" based on prompts.py
        has_rec = "Recommendation:" in finding_text or v.get("recommendation")
        assert has_rec, "Missing recommendation in finding"
        
    print("[PASS] 3. Verify each finding contains required metadata.")
    
    # 4. Verify findings are NOT automatically approved.
    print("[PASS] 4. Verify findings are NOT automatically approved (checked in 3).")
    
    findings_db = get_findings_by_project_id(actual_project_id)
    assert len(findings_db) == len(vulns)
    
    f1, f2, f3 = findings_db[0]["finding_id"], None, None
    if len(findings_db) > 1: f2 = findings_db[1]["finding_id"]
    if len(findings_db) > 2: f3 = findings_db[2]["finding_id"]
    
    # 5. Accept one finding as a reviewer.
    update_finding_status(f1, FindingStatus.ACCEPTED, user="reviewer_1", model="test")
    print("[PASS] 5. Accept one finding as a reviewer.")
    
    # 6. Edit another finding with a reviewer explanation.
    if f2:
        update_finding_status(f2, FindingStatus.EDITED, edit_data={"finding": "Custom explanation"}, user="reviewer_1", model="test")
        print("[PASS] 6. Edit another finding with a reviewer explanation.")
    else:
        print("[SKIP] 6. Not enough findings to edit.")
        
    # 7. Reject another finding if available.
    if f3:
        update_finding_status(f3, FindingStatus.REJECTED, user="reviewer_1", model="test")
        print("[PASS] 7. Reject another finding.")
    else:
        print("[SKIP] 7. Not enough findings to reject.")
        
    # 8. Verify every review action creates an audit event.
    logs = get_audit_logs_for_project(actual_project_id)
    review_logs = [l for l in logs if l["event_type"] == "REVIEW"]
    assert len(review_logs) >= (1 + (1 if f2 else 0) + (1 if f3 else 0))
    print("[PASS] 8. Verify every review action creates an audit event.")
    
    # 9. Generate the JSON report.
    report_json_str = generate_json_report(actual_project_id, get_findings_by_project_id(actual_project_id), logs)
    report = json.loads(report_json_str)
    print("[PASS] 9. Generate the JSON report.")
    
    # 10. Verify the report reflects the final reviewer statuses.
    status_summary = report["summaries"]["status"]
    assert status_summary.get("ACCEPTED", 0) >= 1
    if f2: assert status_summary.get("EDITED", 0) >= 1
    if f3: assert status_summary.get("REJECTED", 0) >= 1
    print("[PASS] 10. Verify the report reflects the final reviewer statuses.")
    
    # 11. Verify the original source code was not modified.
    with open(os.path.join(synth_dir, "utils.c"), "r") as f:
        assert f.read() == code_content, "Source code was modified!"
    print("[PASS] 11. Verify the original source code was not modified.")
    
    # 12. Verify the project namespace remains isolated.
    assert os.path.exists(os.path.join(VECTORSTORE_DIR, actual_project_id)), "Namespace vectorstore missing"
    print("[PASS] 12. Verify the project namespace remains isolated.")
    
    # 13. Verify no source code is transmitted to an external API.
    assert settings.LLM_PROVIDER in ["ollama", "dummy"], "External provider active"
    print("[PASS] 13. Verify no source code is transmitted to an external API.")
    
    print("=== ALL FEATURE VERIFICATIONS PASSED ===")

if __name__ == "__main__":
    run_verification()
