import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from app.security.cppcheck import run_cppcheck_on_code

def main():
    with open(os.path.join(os.path.dirname(__file__), "tests", "sensor.c"), "r") as f:
        code = f.read()
    
    from app.security.static_scan import StaticScanner
    scanner = StaticScanner()
    static_findings = scanner.scan(code)
    print("--- Static Scanner Findings ---")
    for f in static_findings:
        print(f"[{f['category']}] Line {f['line']}: {f['description']} (Code: {f['code']})")
        
    print("\n--- Cppcheck Findings ---")
    findings = run_cppcheck_on_code(code)
    
    for f in findings:
        print(f"[{f['category']}] Line {f['line']}: {f['description']} (Rule: {f['type']})")

if __name__ == "__main__":
    main()
