import time
import requests
from fastapi.testclient import TestClient

from app.main import app
from app.core.config import settings

def main():
    print("=== CONFIG ===")
    print(f"Provider: {settings.LLM_PROVIDER}")
    print(f"Model: {settings.LLM_MODEL}")
    print(f"Ollama URL: {settings.OLLAMA_BASE_URL}")
    
    print("\n=== OLLAMA DIRECT INFERENCE ===")
    start = time.time()
    try:
        res = requests.post(
            f"{settings.OLLAMA_BASE_URL}/api/generate",
            json={"model": settings.LLM_MODEL, "prompt": "Hello", "stream": False}
        )
        print(f"Ollama Response status: {res.status_code}")
        print(f"Ollama Content: {res.json().get('response', '')}")
    except Exception as e:
        print(f"Failed to query Ollama: {e}")
    print(f"Time: {time.time() - start:.2f}s")
    
    print("\n=== API INFERENCE ===")
    client = TestClient(app)
    
    from app.core.auth import get_current_user
    app.dependency_overrides[get_current_user] = lambda: {"username": "admin", "role": "ADMIN", "projects": ["*"]}
    
    code = """
    #include <string.h>
    void vuln(char *src) {
        char dest[10];
        strcpy(dest, src);
    }
    """
    start_analyze = time.time()
    res_analyze = client.post("/api/analyze", json={
        "code": code,
        "language": "c",
        "project_id": "test_project"
    })
    elapsed = time.time() - start_analyze
    
    print(f"Analyze status: {res_analyze.status_code}")
    if res_analyze.status_code == 200:
        vulns = res_analyze.json().get("vulnerabilities", [])
        print(f"Findings: {len(vulns)}")
        for i, v in enumerate(vulns):
            print(f"--- Finding {i+1} ---")
            print(f"Explanation: {v.get('finding')}")
            if settings.LLM_PROVIDER.lower() == "dummy" or "dummy" in v.get('finding', '').lower() or "configuration required" in v.get('finding', '').lower():
                print("FALLBACK: DummyLLM occurred.")
            else:
                print("REAL MODEL INFERENCE CONFIRMED.")
    else:
        print(res_analyze.text)
        
    print(f"Analysis Time: {elapsed:.2f}s")

if __name__ == "__main__":
    main()
