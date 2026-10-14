import requests
import json

base_url = "http://localhost:8000"

# 1. Login
auth_data = {
    "username": "admin",
    "password": "admin123"
}
print("Logging in...")
auth_resp = requests.post(f"{base_url}/api/auth/token", data=auth_data)
if auth_resp.status_code != 200:
    print("Auth failed:", auth_resp.text)
    exit(1)

token = auth_resp.json()["access_token"]
headers = {"Authorization": f"Bearer {token}"}

# 2. Analyze code matching user's case
code = """
void test_strcat(char *str1, char *str2) {
    strcat(str1, str2);
}
"""

req_data = {
    "code": code,
    "language": "c"
}

print("Analyzing code...")
analyze_resp = requests.post(f"{base_url}/api/analyze", json=req_data, headers=headers)
if analyze_resp.status_code != 200:
    print("Analyze failed:", analyze_resp.text)
    exit(1)

findings = analyze_resp.json().get("vulnerabilities", [])
for idx, v in enumerate(findings):
    print(f"--- Finding {idx+1} ---")
    print(f"Evidence: {v.get('evidence')}")
    print(f"Explanation:\n{v.get('finding')}")
    print(f"Explanation Quality: {v.get('explanation_quality')}")
    print()

print(f"Total findings: {len(findings)}")
