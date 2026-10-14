import asyncio
import time
import json
import sys
import os
from dotenv import load_dotenv
load_dotenv(os.path.join(os.path.dirname(__file__), 'backend', '.env'))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), 'backend')))

from app.api.analyze import analyze_code
from app.schemas.request import CodeRequest

test_code = """
#include <stdio.h>
#include <string.h>

void copy_data(char *input) {
    char buffer[10];

    strcpy(buffer, input);
}

void test_pointer() {
    char *ptr = NULL;
    printf("%d\\n", *ptr);
}

int main() {
    char input[100];
    copy_data(input);
    test_pointer();
    return 0;
}
"""

async def run_test():
    start_time = time.time()
    
    request = CodeRequest(code=test_code)
    try:
        response = await analyze_code(request)
        
        analysis_time = time.time() - start_time
        
        print(f"Analysis Time: {analysis_time:.2f} seconds")
        print(f"Total Vulnerabilities: {response.total_vulnerabilities}")
        print("\nFindings:")
        
        for vuln in response.vulnerabilities:
            print("-" * 50)
            print(f"Category: {vuln.type}")
            print(f"Severity: {vuln.severity}")
            print(f"Line: {vuln.line}")
            print(f"Confidence: {vuln.confidence}")
            print(f"Explanation:\n{vuln.explanation}")
            
    except Exception as e:
        print(f"Error during analysis: {e}")

if __name__ == "__main__":
    asyncio.run(run_test())
