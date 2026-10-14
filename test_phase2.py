import os
import shutil
import json

import sys
sys.path.insert(0, os.path.abspath('backend'))
from app.repository.manager import ingest_repository

def create_mock_repo():
    os.makedirs("mock_repo2", exist_ok=True)
    
    with open("mock_repo2/utils.h", "w") as f:
        f.write("""
#ifndef UTILS_H
#define UTILS_H
void copy_data(char *input);
#endif
        """)
        
    with open("mock_repo2/utils.c", "w") as f:
        f.write("""
#include "utils.h"
#include <string.h>

void copy_data(char *input) {
    strcpy(input, "copied");
}
        """)

    with open("mock_repo2/main.c", "w") as f:
        f.write("""
#include <stdio.h>
#include "utils.h"

int main() {
    char buffer[10];
    copy_data(buffer);
    printf("%s\\n", buffer);
    return 0;
}
        """)

def test_phase2():
    try:
        create_mock_repo()
        print("Ingesting repository...")
        repo_data = ingest_repository("mock_repo2")
        
        main_c = next(f for f in repo_data["files"] if f["path"] == "main.c")
        utils_c = next(f for f in repo_data["files"] if f["path"] == "utils.c")
        utils_h = next(f for f in repo_data["files"] if f["path"] == "utils.h")
        
        # main.c asserts
        assert "utils.h" in main_c["dependencies"], "main.c should depend on utils.h"
        assert "copy_data" in main_c["functions"][0]["calls"], "main.c main() should call copy_data"
        assert main_c["functions"][0]["name"] == "main"
        
        # utils.c asserts
        assert "utils.h" in utils_c["dependencies"], "utils.c should depend on utils.h"
        assert "copy_data" == utils_c["functions"][0]["name"], "utils.c should define copy_data"
        assert "strcpy" in utils_c["functions"][0]["calls"], "copy_data should call strcpy"
        
        # utils.h asserts
        assert "copy_data" == utils_h["declarations"][0]["name"], "utils.h should declare copy_data"
        
        print("Phase 2 Acceptance Tests Passed!")
        
    finally:
        shutil.rmtree("mock_repo2", ignore_errors=True)

if __name__ == "__main__":
    test_phase2()
