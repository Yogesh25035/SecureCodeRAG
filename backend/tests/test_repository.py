import os
import pytest
from app.repository.manager import ingest_repository

def test_ingest_demo_repository():
    # Construct path to the synthetic demo repository
    demo_repo_path = os.path.join(os.path.dirname(__file__), '..', 'data', 'demo_repository')
    
    # Ensure the directory exists before testing
    assert os.path.exists(demo_repo_path), "Demo repository must exist for testing"
    
    # Run ingestion
    repo_data = ingest_repository(demo_repo_path)
    
    # Assert core repository metadata
    assert repo_data["path"] == demo_repo_path
    
    # Find files to assert C/C++ ingestion works
    files_ingested = [f["path"] for f in repo_data["files"]]
    
    # Normalize paths for Windows/Linux compatibility
    normalized_files = [f.replace('\\', '/') for f in files_ingested]
    
    assert "src/engine.c" in normalized_files
    assert "src/sensor.c" in normalized_files
    assert "include/engine.h" in normalized_files
    
    # Check function parsing
    engine_c = next((f for f in repo_data["files"] if "engine.c" in f["path"].replace('\\', '/')), None)
    assert engine_c is not None
    assert any(fn["name"] == "calculate_speed" for fn in engine_c["functions"])
    assert any(fn["name"] == "log_engine_status" for fn in engine_c["functions"])
