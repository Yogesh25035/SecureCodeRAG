import sys
import os
import json
import uuid
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.abspath('backend'))
from app.main import app
from app.core.auth import get_current_user
from app.core.config import settings
from app.security.static_scan import StaticScanner

# Mock auth
def override_get_current_user():
    return {"username": "admin", "role": "ADMIN", "projects": ["*"]}

app.dependency_overrides[get_current_user] = override_get_current_user
client = TestClient(app)


def test_division_rule_ignores_comments_and_literals():
    scanner = StaticScanner()

    comment_findings = scanner.scan("// Finding candidate / divisor\nint value = 1;")
    literal_findings = scanner.scan('const char *text = "candidate / divisor";\nint value = 1;')
    actual_findings = scanner.scan(
        "int calculate(int value, int divisor) { return value / divisor; }"
    )

    assert not comment_findings
    assert not literal_findings
    assert [finding["category"] for finding in actual_findings] == ["DIVISION_BY_ZERO"]
    assert actual_findings[0]["line"] == 1
    assert "value / divisor" in actual_findings[0]["code"]


def test_analysis_deduplication_and_report_preserve_sources_and_lines():
    project_id = f"scanner-regression-{uuid.uuid4()}"
    code = """int calculate(int value, int divisor) {
    // Finding candidate / divisor
    char dest[4];
    strcpy(dest, value == 1 ? "safe" : "unsafe");
    return value / divisor;
}
"""
    previous_provider = settings.LLM_PROVIDER
    settings.LLM_PROVIDER = "dummy"

    try:
        response = client.post(
            "/api/analyze",
            json={
                "code": code,
                "language": "c",
                "file_path": "src/calculator.c",
                "project_id": project_id,
            },
        )
        assert response.status_code == 200, response.text

        findings = response.json()["vulnerabilities"]
        categories = [finding["category"] for finding in findings]
        assert categories.count("DIVISION_BY_ZERO") == 1
        assert categories.count("UNSAFE_STRING_OPS") == 1
        assert all(finding["source"] for finding in findings)
        assert all(finding["file"] == "src/calculator.c" for finding in findings)
        assert all(finding["line_start"] > 0 for finding in findings)
        assert not any(
            finding["category"] == "DIVISION_BY_ZERO" and finding["line_start"] == 2
            for finding in findings
        )

        report = client.get(f"/api/reports/{project_id}?format=json")
        assert report.status_code == 200, report.text
        report_data = report.json()
        assert report_data["summaries"]["category"]["DIVISION_BY_ZERO"] == 1
        assert report_data["summaries"]["category"]["UNSAFE_STRING_OPS"] == 1
        report_findings = report_data["findings"]
        assert {finding["file"] for finding in report_findings} == {"src/calculator.c"}
        assert all(finding["line_start"] > 0 for finding in report_findings)
    finally:
        settings.LLM_PROVIDER = previous_provider

def test_strcpy_classification_and_deduplication():
    # Priority 1 and Priority 2 tests
    code = """
void test_func() {
    char dest[10];
    char src[20] = "abcdefghij";
    strcpy(dest, src);
}
"""
    req_data = {
        "code": code,
        "language": "c"
    }
    
    response = client.post("/api/analyze", json=req_data)
    assert response.status_code == 200, response.text
    vulns = response.json().get("vulnerabilities", [])
    
    # Check that strcpy is classified as UNSAFE_STRING_OPS, not Weak Cryptography
    categories = [v.get("category") for v in vulns]
    types = [v.get("type") for v in vulns]
    
    assert "Weak Cryptography" not in categories, "strcpy was incorrectly classified as Weak Cryptography"
    assert "Weak Cryptography" not in types, "strcpy was incorrectly classified as Weak Cryptography"
    
    assert "UNSAFE_STRING_OPS" in categories, "strcpy was not classified as UNSAFE_STRING_OPS"
    
    # Verify deduplication for UNSAFE_STRING_OPS
    unsafe_ops = [v for v in vulns if v.get("category") == "UNSAFE_STRING_OPS"]
    assert len(unsafe_ops) == 1, f"Expected 1 UNSAFE_STRING_OPS finding, got {len(unsafe_ops)}"
    
def test_review_workflow_and_audit():
    # Priority 4: Test reviewer workflow
    # 1. Generate finding
    code = """
void test_func() {
    char dest[10];
    strcpy(dest, "abc");
}
"""
    response = client.post("/api/analyze", json={"code": code, "language": "c"})
    assert response.status_code == 200
    vulns = response.json().get("vulnerabilities", [])
    assert len(vulns) > 0
    finding_id = vulns[0]["finding_id"]
    
    # 2. Test Accept
    accept_res = client.post(f"/api/review/{finding_id}/accept")
    assert accept_res.status_code == 200, f"Accept failed: {accept_res.text}"
    
    # 3. Test Reject
    reject_res = client.post(f"/api/review/{finding_id}/reject", json={"reason": "False positive"})
    assert reject_res.status_code == 200, f"Reject failed: {reject_res.text}"
    
    # 4. Test Edit
    edit_res = client.post(f"/api/review/{finding_id}/edit", json={"severity": "LOW"})
    assert edit_res.status_code == 200, f"Edit failed: {edit_res.text}"
    
    # 5. Test Audit retrieval
    audit_res = client.get("/api/review/system/audit")
    assert audit_res.status_code == 200, f"Audit failed: {audit_res.text}"
    logs = audit_res.json()
    assert len(logs) > 0
    finding_logs = [log for log in logs if log["finding_id"] == finding_id]
    assert len(finding_logs) >= 3, "Missing audit logs for Accept, Reject, Edit"

def test_report_generation():
    # Priority 5: Verify reports
    report_res = client.get("/api/reports/unknown?format=json")
    assert report_res.status_code in [200, 404] # Depending on if 'unknown' project exists, 404 is fine if not

if __name__ == "__main__":
    print("Testing division comment and literal filtering...")
    test_division_rule_ignores_comments_and_literals()
    print("Testing analysis deduplication and report preservation...")
    test_analysis_deduplication_and_report_preserve_sources_and_lines()
    print("Testing strcpy classification and deduplication...")
    test_strcpy_classification_and_deduplication()
    print("Testing review workflow and audit endpoints...")
    test_review_workflow_and_audit()
    print("Testing report generation...")
    test_report_generation()
    print("All regression tests passed successfully!")
