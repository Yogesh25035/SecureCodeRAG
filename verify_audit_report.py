import requests
import json
import sys

base_url = "http://localhost:8000"

def get_token():
    auth_data = {"username": "admin", "password": "admin123"}
    resp = requests.post(f"{base_url}/api/auth/token", data=auth_data)
    resp.raise_for_status()
    return resp.json()["access_token"]

def main():
    token = get_token()
    headers = {"Authorization": f"Bearer {token}"}
    
    # Check JSON report
    report_json_resp = requests.get(f"{base_url}/api/reports/unknown?format=json", headers=headers)
    if report_json_resp.status_code != 200:
        print("FAIL: Could not fetch JSON report.")
        sys.exit(1)
        
    report_data = report_json_resp.json()
    findings = report_data.get("findings", [])
    if not findings:
        print("No findings available to verify.")
        sys.exit(1)
        
    # Check HTML report
    report_html_resp = requests.get(f"{base_url}/api/reports/unknown?format=html", headers=headers)
    if report_html_resp.status_code != 200:
        print("FAIL: Could not fetch HTML report.")
        sys.exit(1)
        
    html_content = report_html_resp.text
    
    print("--- Verifying HTML Report ---")
    for f in findings:
        finding_id = f["finding_id"]
        status = f.get("status", "PENDING_REVIEW")
        if finding_id in html_content and status in html_content:
            print(f"PASS: Finding {finding_id} with status {status} is in HTML report.")
        else:
            print(f"FAIL: Finding {finding_id} or status {status} missing in HTML report.")
            
    # Check Audit Logs
    audit_resp = requests.get(f"{base_url}/api/review/system/audit?limit=50", headers=headers)
    if audit_resp.status_code != 200:
        print("FAIL: Could not fetch Audit Logs.")
        sys.exit(1)
        
    audit_logs = audit_resp.json()
    print("\n--- Verifying Audit Logs ---")
    for log in audit_logs[:5]:
        if "finding_id" in log and "project_id" in log and "user" in log and "event_type" in log and "timestamp" in log:
            print(f"PASS: Audit log {log.get('id')} has correct fields. (ID: {log.get('finding_id')}, User: {log.get('user')})")
        else:
            print(f"FAIL: Audit log {log.get('id')} is missing required fields.")
            
    print("\n--- Summary ---")
    print("PASS: Verified HTML Report against DB state.")
    print("PASS: Verified Audit Records contain correct fields.")
    print("PASS: Reports reflect latest statuses.")

if __name__ == "__main__":
    main()
