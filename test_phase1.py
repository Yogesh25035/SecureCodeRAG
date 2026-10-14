import asyncio
import os
import zipfile
import shutil
from fastapi.testclient import TestClient

import sys
sys.path.insert(0, os.path.abspath('backend'))
from app.main import app

client = TestClient(app)

def create_mock_repo():
    os.makedirs("mock_repo/src", exist_ok=True)
    os.makedirs("mock_repo/node_modules", exist_ok=True)
    os.makedirs("mock_repo/build", exist_ok=True)
    
    # Valid file
    with open("mock_repo/src/main.c", "w") as f:
        f.write("int main() { return 0; }")
        
    # Another valid file
    with open("mock_repo/src/utils.h", "w") as f:
        f.write("void helper();")
        
    # Duplicate file
    with open("mock_repo/src/main_copy.c", "w") as f:
        f.write("int main() { return 0; }")
        
    # Ignored directory file
    with open("mock_repo/node_modules/bad.c", "w") as f:
        f.write("int bad() {}")
        
    # Invalid extension
    with open("mock_repo/src/readme.md", "w") as f:
        f.write("hello")
        
    with zipfile.ZipFile("mock_repo.zip", "w") as zf:
        for root, _, files in os.walk("mock_repo"):
            for file in files:
                zf.write(os.path.join(root, file), os.path.relpath(os.path.join(root, file), "mock_repo"))

def test_upload():
    print("Testing repo upload...")
    with open("mock_repo.zip", "rb") as f:
        response = client.post("/api/repositories/upload", files={"file": ("mock_repo.zip", f, "application/zip")})
    
    assert response.status_code == 200, f"Upload failed: {response.text}"
    data = response.json()
    assert data["status"] == "success"
    # Should only ingest main.c and utils.h (main_copy.c is duplicate, bad.c is ignored, readme.md is invalid)
    assert data["files_ingested"] == 2, f"Expected 2 files, got {data['files_ingested']}"
    print("Upload test passed. Repo ID:", data["repo_id"])
    return data["repo_id"]

def test_analyze(repo_id):
    print("Testing single-file analysis without repo_id...")
    req_data = {
        "code": "void test() { char buffer[10]; char *ptr = NULL; strcpy(buffer, \"hello\"); printf(\"%d\", *ptr); }",
        "language": "c"
    }
    response = client.post("/api/analyze", json=req_data)
    assert response.status_code == 200, f"Analyze failed: {response.text}"
    assert response.json()["total_vulnerabilities"] > 0
    print("Single-file analysis without repo_id passed.")
    
    print("Testing single-file analysis with repo_id...")
    req_data["repo_id"] = repo_id
    response = client.post("/api/analyze", json=req_data)
    assert response.status_code == 200, f"Analyze with repo_id failed: {response.text}"
    assert response.json()["total_vulnerabilities"] > 0
    print("Single-file analysis with repo_id passed.")

def cleanup():
    shutil.rmtree("mock_repo", ignore_errors=True)
    if os.path.exists("mock_repo.zip"):
        os.remove("mock_repo.zip")

if __name__ == "__main__":
    try:
        create_mock_repo()
        repo_id = test_upload()
        test_analyze(repo_id)
        print("\nAll Phase 1 tests passed successfully!")
    finally:
        cleanup()
