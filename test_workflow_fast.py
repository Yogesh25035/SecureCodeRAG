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
    
    print("Fetching existing reports to find a finding...")
    report_resp = requests.get(f"{base_url}/api/reports/unknown?format=json", headers=headers)
    if report_resp.status_code != 200:
        print("No report / findings found. Status:", report_resp.status_code)
        return
        
    report_data = report_resp.json()
    findings = report_data.get("findings", [])
    if not findings:
        print("No findings in the report.")
        return
        
    finding_id = findings[-1]["finding_id"] # grab the last one
    print(f"Testing on Finding ID: {finding_id}")
    
    print("\n1. Testing Accept workflow...")
    accept_resp = requests.post(f"{base_url}/api/review/{finding_id}/accept", headers=headers)
    print("Accept response:", accept_resp.status_code, accept_resp.text)
    
    print("\n2. Testing Edit workflow...")
    edit_data = {"severity": "CRITICAL", "finding": "Edited explanation via audit test."}
    edit_resp = requests.post(f"{base_url}/api/review/{finding_id}/edit", json=edit_data, headers=headers)
    print("Edit response:", edit_resp.status_code, edit_resp.text)
    
    print("\n3. Testing Reject workflow...")
    reject_data = {"reason": "False positive test for audit log"}
    reject_resp = requests.post(f"{base_url}/api/review/{finding_id}/reject", json=reject_data, headers=headers)
    print("Reject response:", reject_resp.status_code, reject_resp.text)
    
    print("\n4. Testing Audit log...")
    audit_resp = requests.get(f"{base_url}/api/review/system/audit?limit=50", headers=headers)
    audit_logs = audit_resp.json()
    my_logs = [log for log in audit_logs if log.get("finding_id") == finding_id]
    for log in my_logs:
        print(f"Audit event: {log.get('event_type')}, Status: {log.get('review_status')}, User: {log.get('user')}, Edits: {log.get('edit_details')}")

    print("\n5. Testing Report Generation Updates...")
    report_resp2 = requests.get(f"{base_url}/api/reports/unknown?format=json", headers=headers)
    report_data2 = report_resp2.json()
    f = next((f for f in report_data2.get("findings", []) if f["finding_id"] == finding_id), None)
    if f:
        print(f"Finding current status in report: {f.get('status')}")

if __name__ == "__main__":
    main()
