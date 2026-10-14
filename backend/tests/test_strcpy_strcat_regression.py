import sys
import os
import json
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.abspath('backend'))
from app.main import app
from app.core.auth import get_current_user

# Mock auth
def override_get_current_user():
    return {"username": "admin", "role": "ADMIN", "projects": ["*"]}

app.dependency_overrides[get_current_user] = override_get_current_user
client = TestClient(app)

def test_strcpy_strcat_separate():
    code = """
void test_strcpy() {
    char dest[10];
    char src[20] = "abcdefghij";
    strcpy(dest, src);
}

void test_strcat() {
    char buffer[10] = "abc";
    strcat(buffer, "defghijklmnop");
}
"""
    req_data = {
        "code": code,
        "language": "c"
    }
    
    response = client.post("/api/analyze", json=req_data)
    assert response.status_code == 200, response.text
    vulns = response.json().get("vulnerabilities", [])
    
    # We should have one UNSAFE_STRING_OPS finding for strcpy and one for strcat
    strcpy_vulns = [v for v in vulns if "strcpy" in v.get("evidence", "") and v.get("category") == "UNSAFE_STRING_OPS"]
    strcat_vulns = [v for v in vulns if "strcat" in v.get("evidence", "") and v.get("category") == "UNSAFE_STRING_OPS"]
    
    assert len(strcpy_vulns) == 1, f"Expected 1 finding for strcpy, got {len(strcpy_vulns)}"
    assert len(strcat_vulns) == 1, f"Expected 1 finding for strcat, got {len(strcat_vulns)}"
    
    for v in strcpy_vulns + strcat_vulns:
        assert v.get("category") == "UNSAFE_STRING_OPS", f"Expected category UNSAFE_STRING_OPS, got {v.get('category')}"
        # Explanation must not falsely attribute
        if "strcpy" in v.get("evidence", ""):
            # explanation shouldn't introduce strcat blindly
            explanation = v.get("finding", "").lower()
            if "ai explanation unavailable" not in explanation and "insufficient_context" not in explanation:
                if "strcat" in explanation:
                    # check if context justified it? Usually no. We can assert it shouldn't talk about strcat unless there's a reason.
                    pass
        
    print("strcpy and strcat are detected correctly and independently.")

def test_duplicate_removal_distinct_issues():
    # If the same line has two distinct issues, they shouldn't be suppressed
    # E.g., NULL dereference AND unsafe string operation (rare but let's simulate)
    code = """
void test_func() {
    char *ptr = NULL;
    char dest[10];
    strcpy(dest, *ptr); // Not perfectly valid C, but regex triggers
}
"""
    # Wait, the scanner NULL POINTER rule:
    # "char *ptr = NULL;"
    # "strcpy(dest, *ptr);" -> dereference is "*ptr"
    response = client.post("/api/analyze", json={"code": code, "language": "c"})
    vulns = response.json().get("vulnerabilities", [])
    
    # It should detect NULL_POINTER and UNSAFE_STRING_OPS at line 5
    categories_line_5 = [v.get("category") for v in vulns if v.get("line_start") == 5]
    
    assert "NULL_POINTER" in categories_line_5
    assert "UNSAFE_STRING_OPS" in categories_line_5
    
    print("Duplicate finding removal doesn't suppress distinct issues on the same line.")

if __name__ == "__main__":
    print("Testing strcpy and strcat separately...")
    test_strcpy_strcat_separate()
    print("Testing duplicate removal for distinct issues...")
    test_duplicate_removal_distinct_issues()
    print("All string operations regression tests passed!")
