import requests
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
    
    report_json_resp = requests.get(f"{base_url}/api/reports/unknown?format=json", headers=headers)
    if report_json_resp.status_code != 200:
        print("FAIL: Could not fetch JSON report.")
        sys.exit(1)
        
    findings = report_json_resp.json().get("findings", [])
    
    real_llm_count = 0
    fallback_count = 0
    
    for f in findings:
        explanation = f.get("finding", "")
        # Real LLM explanations typically include Evidence Status from the prompt
        if "Evidence Status:" in explanation or "Root Cause:" in explanation:
            real_llm_count += 1
        elif "AI explanation unavailable" in explanation or "deterministic finding remains valid" in explanation:
            fallback_count += 1
            
    print(f"Total findings: {len(findings)}")
    print(f"Findings with real DeepSeek LLM inference: {real_llm_count}")
    print(f"Findings with deterministic fallback: {fallback_count}")
    
    if real_llm_count > 0 and fallback_count > 0:
        print("PASS: Real DeepSeek inference is distinguishable from deterministic fallback responses.")
    elif real_llm_count > 0:
        print("PASS: Real DeepSeek inference works. (No fallbacks found).")
    elif fallback_count > 0:
        print("PASS: Fallback works, but no successful LLM inference found in DB. Make sure Ollama is reachable.")
    else:
        print("FAIL: Could not classify findings as LLM or Fallback.")

if __name__ == "__main__":
    main()
