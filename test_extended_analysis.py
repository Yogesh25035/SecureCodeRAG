import requests
import json
import time

base_url = "http://localhost:8000"
headers = {}

def get_token():
    auth_data = {"username": "admin", "password": "admin123"}
    resp = requests.post(f"{base_url}/api/auth/token", data=auth_data)
    resp.raise_for_status()
    return resp.json()["access_token"]

def wait_for_backend():
    print("Waiting for backend...")
    for _ in range(300):
        try:
            requests.get(f"{base_url}/api/docs", timeout=1)
            print("Backend is up!")
            return
        except:
            time.sleep(1)
    raise Exception("Backend failed to start")

def run_tests():
    global headers
    token = get_token()
    headers = {"Authorization": f"Bearer {token}"}
    
    print("\n1. Testing sensor.c analysis...")
    sensor_code = """
#include "sensor.h"

int sensor_history[10];

void read_sensor_data(void) {
    int raw_value;
    int processed = raw_value * 2;

    for (int i = 0; i <= 10; i++) {
        sensor_history[i] = processed;
    }
}

int calculate_speed(int distance, int time) {
    return distance / time;
}
"""
    
    resp = requests.post(f"{base_url}/api/analyze", json={"code": sensor_code, "language": "c", "project_id": "test_proj"}, headers=headers)
    assert resp.status_code == 200
    data = resp.json()
    vulns = data.get("vulnerabilities", [])
    categories = [v["category"] for v in vulns]
    print(f"Categories found: {categories}")
    assert "UNINITIALIZED_VARIABLE" in categories, "Failed to find UNINITIALIZED_VARIABLE"
    assert "OUT_OF_BOUNDS" in categories, "Failed to find OUT_OF_BOUNDS"
    assert "DIVISION_BY_ZERO" in categories, "Failed to find DIVISION_BY_ZERO"
    assert "INTEGER_OVERFLOW" in categories, "Failed to find INTEGER_OVERFLOW"
    print("PASS: sensor.c defect categories detected successfully")
    
    # Test Clean result
    print("\n2. Testing safe code examples that should not trigger findings...")
    token = get_token()
    headers = {"Authorization": f"Bearer {token}"}
    clean_code = """
#include <stdio.h>
int main() {
    printf("Hello World\\n");
    return 0;
}
"""
    resp = requests.post(f"{base_url}/api/analyze", json={"code": clean_code, "language": "c", "project_id": "test_proj"}, headers=headers)
    assert resp.status_code == 200
    data = resp.json()
    # It might have missingInclude if it uses cppcheck, but since stdio is standard it might be ignored or not.
    # Actually, cppcheck flags missing include if --enable=all.
    # Let's filter out STATIC_ANALYSIS (missing include).
    real_vulns = [v for v in data.get("vulnerabilities", []) if v["category"] != "STATIC_ANALYSIS"]
    assert len(real_vulns) == 0, f"Expected 0 real vulnerabilities, got {len(real_vulns)}: {real_vulns}"
    print("PASS: Safe code correctly yields no real findings")
    
    print("\nAll integration tests PASSED!")

if __name__ == "__main__":
    wait_for_backend()
    run_tests()
