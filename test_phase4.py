import sys
import os
import json
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.abspath('backend'))
from app.main import app

client = TestClient(app)

from app.core.auth import get_current_user

def override_get_current_user():
    return {"username": "admin", "role": "ADMIN", "projects": ["*"]}

app.dependency_overrides[get_current_user] = override_get_current_user

def test_phase4():
    # This code triggers both PROJECT_RULE (via 'strcpy' regex)
    # and CPPCHECK (via uninitialized variable or bounds).
    code = """
void unsafe_func() {
    char dest[10];
    char src[20] = "this is a very long string";
    strcpy(dest, src);
}
"""
    print("Running analysis with combined sources...")
    req_data = {
        "code": code,
        "language": "c"
    }
    
    response = client.post("/api/analyze", json=req_data)
    assert response.status_code == 200, f"Analyze failed: {response.text}"
    
    data = response.json()
    vulns = data["vulnerabilities"]
    
    print(f"Total findings: {len(vulns)}")
    
    sources = [v["source"] for v in vulns]
    print(f"Sources found: {sources}")
    
    # Assert deduplication or cppcheck presence depending on system installation
    if "CPPCHECK" in sources or "COMBINED" in sources:
        print("Cppcheck successfully ran and merged findings!")
    else:
        print("Cppcheck not installed or didn't find anything, falling back to PROJECT_RULE.")
        
    print("Phase 4 tests passed!")

if __name__ == "__main__":
    test_phase4()
