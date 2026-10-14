import os
import shutil
import pytest
from pathlib import Path
from app.vectorstore.index import create_vectorstore, get_vectorstore, add_repository_to_vectorstore, VECTORSTORE_DIR
from app.rag.retriever import VulnerabilityRetriever

@pytest.fixture(autouse=True)
def clean_vectorstore():
    # Setup: ensure clean test namespace
    test_ns1 = "test_repo_1"
    test_ns2 = "test_repo_2"
    
    for ns in [test_ns1, test_ns2]:
        p = VECTORSTORE_DIR / ns
        if p.exists():
            shutil.rmtree(p)
            
    yield
    
    # Teardown
    for ns in [test_ns1, test_ns2]:
        p = VECTORSTORE_DIR / ns
        if p.exists():
            shutil.rmtree(p)

def test_cross_project_isolation():
    # 1. Add repo 1
    repo1_data = {
        "project_id": "test_repo_1",
        "project_name": "Project Alpha",
        "files": [
            {
                "path": "alpha.c",
                "type": "c",
                "content": "void alpha_vulnerable() { // EXTREMELY SPECIFIC SQL INJECTION IN ALPHA }",
                "functions": []
            }
        ]
    }
    add_repository_to_vectorstore(repo1_data)
    
    # 2. Add repo 2
    repo2_data = {
        "project_id": "test_repo_2",
        "project_name": "Project Beta",
        "files": [
            {
                "path": "beta.c",
                "type": "c",
                "content": "void beta_vulnerable() { // EXTREMELY SPECIFIC SQL INJECTION IN BETA }",
                "functions": []
            }
        ]
    }
    add_repository_to_vectorstore(repo2_data)
    
    # 3. Retrieve using Repo 1
    retriever = VulnerabilityRetriever()
    docs1 = retriever.retrieve("EXTREMELY SPECIFIC SQL INJECTION", project_id="test_repo_1")
    
    # Check that alpha is in docs1, but NOT beta
    alpha_found = any("ALPHA" in d.page_content for d in docs1)
    beta_found = any("BETA" in d.page_content for d in docs1)
    
    assert alpha_found == True, "Project Alpha content should be retrieved for Repo 1"
    assert beta_found == False, "Project Beta content MUST NEVER leak into Repo 1 context"
    
    # 4. Retrieve using Repo 2
    docs2 = retriever.retrieve("EXTREMELY SPECIFIC SQL INJECTION", project_id="test_repo_2")
    
    alpha_found_2 = any("ALPHA" in d.page_content for d in docs2)
    beta_found_2 = any("BETA" in d.page_content for d in docs2)
    
    assert beta_found_2 == True, "Project Beta content should be retrieved for Repo 2"
    assert alpha_found_2 == False, "Project Alpha content MUST NEVER leak into Repo 2 context"
