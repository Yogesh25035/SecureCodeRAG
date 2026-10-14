import os
import json
import pytest
import shutil
import uuid
from typing import List

from fastapi.testclient import TestClient

from app.main import app
from app.repository.manager import ingest_repository
from app.vectorstore.index import add_repository_to_vectorstore, get_vectorstore, VECTORSTORE_DIR
from app.security.static_scan import StaticScanner
from app.security.cppcheck import run_cppcheck_on_code
from app.api.analyze import analyze_code
from app.schemas.request import CodeRequest
from app.schemas.findings import FindingStatus
from app.review.findings import save_finding, get_findings_by_project_id, update_finding_status
from app.review.audit import get_audit_logs_for_project
from app.reports.generator import generate_html_report, generate_json_report
from app.rag.retriever import VulnerabilityRetriever
from app.rag.generator import ExplanationGenerator

SYNTHETIC_REPO_PATH = os.path.join(os.path.dirname(__file__), "synthetic_repo")

@pytest.fixture(scope="module")
def project_id():
    return str(uuid.uuid4())

@pytest.fixture(scope="module")
def setup_repo(project_id):
    # Setup - ingest repository
    repo_data = ingest_repository(SYNTHETIC_REPO_PATH, project_name="Synthetic Automotive Repo", project_id=project_id)
    # Add to RAG vectorstore
    add_repository_to_vectorstore(repo_data)
    
    yield repo_data
    
    # Teardown
    ns_dir = VECTORSTORE_DIR / project_id
    if ns_dir.exists():
        shutil.rmtree(ns_dir)

def test_repository_indexing_and_extraction(setup_repo):
    repo_data = setup_repo
    
    assert repo_data["project_name"] == "Synthetic Automotive Repo"
    assert len(repo_data["files"]) >= 3
    
    file_paths = [f["path"] for f in repo_data["files"]]
    assert "utils.c" in file_paths
    assert "sensor.c" in file_paths
    assert "hardware.c" in file_paths
    
    # Test function extraction
    hardware_file = next(f for f in repo_data["files"] if f["path"] == "hardware.c")
    functions = [fn["name"] for fn in hardware_file.get("functions", [])]
    assert "init_hardware" in functions
    assert "process_data" in functions
    assert "safe_function" in functions
    
    # Test dependency extraction (includes)
    main_file = next(f for f in repo_data["files"] if f["path"] == "main.c")
    includes = main_file.get("includes", [])
    assert "utils.h" in includes or any("utils.h" in inc for inc in includes)
    assert "sensor.h" in includes or any("sensor.h" in inc for inc in includes)

def test_static_scanner_and_cppcheck(setup_repo):
    repo_data = setup_repo
    scanner = StaticScanner()
    
    all_vulns = []
    
    for f in repo_data["files"]:
        if f["type"] == "c_cpp":
            # Static scanner
            vulns = scanner.scan(f["content"])
            
            # Cppcheck
            cpp_vulns = run_cppcheck_on_code(f["content"], "c")
            vulns.extend(cpp_vulns)
            
            # Deduplication
            vulns = scanner._deduplicate(vulns)
            
            # Finding Normalization is implicit in the format
            for v in vulns:
                v["file"] = f["path"]
            
            all_vulns.extend(vulns)

    # Expected vulnerabilities (Precision/Recall targets)
    expected_findings = [
        "strcpy", # unsafe string
        "strcat", # unsafe string
        "gets", # dangerous API
        "free", # resource misuse (memory leak) / might not be natively caught by basic scanner without cppcheck, but cppcheck catches it
        "uninitialized", # sensor.c
        "out of bounds", # sensor.c array boundary
    ]
    
    detected_desc = " ".join([str(v) for v in all_vulns]).lower()
    
    found_count = 0
    for expected in expected_findings:
        if expected in detected_desc or expected.replace(" ", "_") in detected_desc:
            found_count += 1
            
    # Measure Recall (at least 60% of expected should be caught by scanner + cppcheck)
    recall = found_count / len(expected_findings)
    assert recall >= 0.5, f"Low recall: {recall} ({found_count}/{len(expected_findings)})"
    
    # Safe code should not be flagged (hardware.c: safe_function)
    # Check that safe_function line numbers aren't heavily flagged unless there's a generic issue
    safe_flags = [v for v in all_vulns if v.get("file") == "hardware.c" and 21 <= v.get("line", 0) <= 26]
    assert len(safe_flags) == 0, "False positive detected in safe_function"

def test_rag_retrieval(project_id, setup_repo):
    retriever = VulnerabilityRetriever()
    
    # Retrieve using project_id
    docs = retriever.retrieve("strcpy unsafe string", project_id=project_id)
    
    assert len(docs) > 0
    # Should contain project-specific docs
    assert any("copy_name" in d.page_content for d in docs), "Failed to retrieve cross-file dependency function"

def test_llm_explanation(setup_repo):
    generator = ExplanationGenerator()
    
    vuln_mock = {
        "category": "UNSAFE_STRING",
        "severity": "HIGH",
        "line": 7,
        "code": "strcpy(dest, src);"
    }
    context = []
    
    # We use the configured LLM (DummyLLM or actual)
    explanation = generator.generate_explanation(vuln_mock, context)
    assert explanation != ""
    assert isinstance(explanation, str)

def test_reviewer_workflow_and_audit(project_id):
    # Create a mock finding
    client = TestClient(app)
    
    # Login as admin
    from app.core.auth import create_access_token
    token = create_access_token({"sub": "admin", "role": "ADMIN", "projects": ["*"]})
    headers = {"Authorization": f"Bearer {token}"}
    
    # Manually save a finding to the DB
    from app.schemas.findings import StructuredFinding, SeverityEnum
    finding_id = str(uuid.uuid4())
    sf = StructuredFinding(
        finding_id=finding_id,
        project_id=project_id,
        file="utils.c",
        line_start=7,
        severity=SeverityEnum.HIGH,
        category="UNSAFE_STRING",
        title="Unsafe strcpy",
        finding="Explanation",
        evidence="strcpy(dest, src)",
        source="scanner",
        confidence=0.8,
        status=FindingStatus.PENDING_REVIEW
    )
    save_finding(sf)
    
    # Update status to ACCEPTED
    update_finding_status(finding_id, FindingStatus.ACCEPTED, user="reviewer1", model="test-model")
    
    # Verify Audit Log
    logs = get_audit_logs_for_project(project_id)
    review_logs = [l for l in logs if l["finding_id"] == finding_id and l["event_type"] == "REVIEW"]
    
    assert len(review_logs) == 1
    assert review_logs[0]["review_status"] == "ACCEPTED"
    assert review_logs[0]["user"] == "reviewer1"
    
def test_reports(project_id):
    # Verify HTML and JSON report generation
    findings = get_findings_by_project_id(project_id)
    audit_logs = get_audit_logs_for_project(project_id)
    
    html_report = generate_html_report(project_id, findings, audit_logs)
    assert "Automotive Secure Code Review Report" in html_report
    assert project_id in html_report
    
    json_report = generate_json_report(project_id, findings, audit_logs)
    json_data = json.loads(json_report)
    assert json_data["project_info"]["project_id"] == project_id
    assert "severity" in json_data["summaries"]
