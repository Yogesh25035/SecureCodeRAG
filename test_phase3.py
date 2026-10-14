import sys
import os
sys.path.insert(0, os.path.abspath('backend'))
from app.security.code_context import get_code_context
from app.repository.parser import parse_c_file

def test_phase3():
    code = """
#include <stdio.h>
#include <stdlib.h>

void use(char *ptr) {
    if (ptr != NULL) {
        printf("using ptr");
        *ptr = 'A';
    } else {
        return;
    }
}
"""
    # 1. Parse code to get function bounds
    parsed = parse_c_file(code)
    func = parsed["functions"][0]
    
    # Target line: *ptr = 'A'; (line 9)
    # Let's see what get_code_context gives us.
    context = get_code_context(code, 8, func_start=func["start_line"], func_end=func["end_line"])
    print(context)
    
    assert "--- CONTROL FLOW SUMMARY ---" in context
    assert "Resource/Pointer operation at line 6: if (ptr != NULL) {" in context
    assert "Target line is enclosed in:" in context
    assert "Line 6: if (ptr != NULL) {" in context
    assert "Early return/break at line 10: return;" in context
    
    print("Phase 3 tests passed!")

if __name__ == "__main__":
    test_phase3()
