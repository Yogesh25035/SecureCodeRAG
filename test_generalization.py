import sys
import os
import requests

sys.path.insert(0, os.path.abspath('backend'))
base_url = "http://localhost:8000"

def get_token():
    auth_data = {"username": "admin", "password": "admin123"}
    resp = requests.post(f"{base_url}/api/auth/token", data=auth_data)
    resp.raise_for_status()
    return resp.json()["access_token"]

def analyze_code(code):
    token = get_token()
    headers = {"Authorization": f"Bearer {token}"}
    req_data = {"code": code, "language": "c"}
    response = requests.post(f"{base_url}/api/analyze", json=req_data, headers=headers)
    response.raise_for_status()
    return response.json().get("vulnerabilities", [])

def test_safe_code():
    code = """
    #include <string.h>
    void test_safe() {
        char dest[20];
        const char *src = "safe_string";
        strncpy(dest, src, sizeof(dest) - 1);
        dest[sizeof(dest) - 1] = '\\0';
    }
    """
    findings = analyze_code(code)
    # We shouldn't get UNSAFE_STRING_OPS because we used strncpy
    unsafe = [f for f in findings if f.get("category") == "UNSAFE_STRING_OPS"]
    assert len(unsafe) == 0, f"Expected 0 unsafe string ops, got {len(unsafe)}"
    print("PASS: Safe code (strncpy) does not trigger UNSAFE_STRING_OPS")

def test_different_category():
    code = """
    void connect_db() {
        char *password = "super_secret_p4ssw0rd!";
    }
    """
    findings = analyze_code(code)
    hardcoded = [f for f in findings if f.get("category") == "HARDCODED_SECRETS"]
    assert len(hardcoded) > 0, "Expected HARDCODED_SECRETS finding"
    print("PASS: Different category (HARDCODED_SECRETS) is detected correctly")

def test_modified_variables():
    # Similar to strcpy but with different var names and structure
    code = """
    void data_transfer() {
        char target_buffer[50];
        char incoming_payload[100];
        // some code
        strcpy(target_buffer, incoming_payload);
    }
    """
    findings = analyze_code(code)
    strcpy_findings = [f for f in findings if f.get("category") == "UNSAFE_STRING_OPS" and "strcpy" in f.get("evidence", "")]
    assert len(strcpy_findings) > 0, "Expected strcpy finding despite modified variable names"
    
    finding = strcpy_findings[0]
    explanation = finding.get("finding", "")
    print("PASS: Modified variable names still trigger strcpy finding.")
    print(f"Explanation snippet: {explanation[:100]}...")

if __name__ == "__main__":
    test_safe_code()
    test_different_category()
    test_modified_variables()
    print("All generalization tests passed!")
