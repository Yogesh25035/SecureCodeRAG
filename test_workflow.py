import requests
import json
import time

base_url = "http://localhost:8000"

def get_token():
    auth_data = {"username": "admin", "password": "admin123"}
    resp = requests.post(f"{base_url}/api/auth/token", data=auth_data)
    resp.raise_for_status()
    return resp.json()["access_token"]

def main():
    token = get_token()
    headers = {"Authorization": f"Bearer {token}"}
    
    code = """
    void workflow_test() {
        char buf[10];
        strcpy(buf, "test");
    }
    """
    print("1. Sending code for analysis...")
    resp = requests.post(f"{base_url}/api/analyze", json={"code": code, "language": "c"}, headers=headers)
    resp.raise_for_status()
    
    findings = resp.json().get("vulnerabilities", [])
    if not findings:
        print("No findings returned.")
        return
        
    finding_id = findings[0]["finding_id"]
    print(f"Finding ID: {finding_id}, Status: {findings[0].get('status')}")
    
    print("\n2. Testing Accept workflow...")
    accept_resp = requests.post(f"{base_url}/api/review/{finding_id}/accept", headers=headers)
    print("Accept response:", accept_resp.status_code)
    
    print("\n3. Testing Edit workflow...")
    edit_data = {"severity": "CRITICAL", "finding": "Edited explanation."}
    edit_resp = requests.post(f"{base_url}/api/review/{finding_id}/edit", json=edit_data, headers=headers)
    print("Edit response:", edit_resp.status_code)
    
    print("\n4. Testing Reject workflow...")
    reject_data = {"reason": "False positive test"}
    reject_resp = requests.post(f"{base_url}/api/review/{finding_id}/reject", json=reject_data, headers=headers)
    print("Reject response:", reject_resp.status_code)
    
    print("\n5. Testing Audit log...")
    audit_resp = requests.get(f"{base_url}/api/review/system/audit", headers=headers)
    audit_logs = audit_resp.json()
    my_logs = [log for log in audit_logs if log.get("finding_id") == finding_id]
    for log in my_logs:
        print(f"Audit event: {log.get('event_type')}, Status: {log.get('review_status')}, User: {log.get('user')}, Edits: {log.get('edit_details')}")

    print("\n6. Testing Report Generation (JSON)...")
    report_resp = requests.get(f"{base_url}/api/reports/unknown?format=json", headers=headers)
    print("Report status:", report_resp.status_code)
    if report_resp.status_code == 200:
        report_data = report_resp.json()
        print("Total findings in report:", report_data.get("total_findings", 0))

if __name__ == "__main__":
    main()
