from fastapi import APIRouter, HTTPException, UploadFile, File, Depends
from typing import Dict, Any
import os
import shutil
import uuid
import zipfile
from ..schemas.request import RepositoryRequest
from ..repository.manager import ingest_repository
from ..core.auth import require_role

router = APIRouter()

@router.post("/upload")
async def upload_repo(
    file: UploadFile = File(...),
    current_user: dict = Depends(require_role(["ADMIN"]))
) -> Dict[str, Any]:
    """
    Uploads and ingests a zipped repository.
    """
    if not file.filename.endswith('.zip'):
        raise HTTPException(status_code=400, detail="Only ZIP files are supported")
        
    # Prevent oversized zips
    file.file.seek(0, 2)
    file_size = file.file.tell()
    file.file.seek(0)
    if file_size > 50 * 1024 * 1024:
        raise HTTPException(status_code=413, detail="Zip file too large")
        
    project_id = str(uuid.uuid4())
    project_name = file.filename[:-4]
    
    # Store inside data/repos
    base_dir = os.path.join(os.path.dirname(__file__), "..", "data", "repos")
    upload_dir = os.path.join(base_dir, project_id)
    os.makedirs(upload_dir, exist_ok=True)
    zip_path = os.path.join(upload_dir, file.filename)
    
    with open(zip_path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)
        
    try:
        # Validate structure/path traversal during unzip
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            for member in zip_ref.namelist():
                if '..' in member or member.startswith('/') or member.startswith('\\') or os.path.isabs(member):
                    raise HTTPException(status_code=400, detail="Invalid zip file: path traversal attempt")
            zip_ref.extractall(upload_dir)
            
        os.remove(zip_path) # Clean up zip
        
        # Ingest the extracted repo
        repo_data = ingest_repository(upload_dir, project_name=project_name, project_id=project_id)
        
        # Add to RAG
        from ..vectorstore.index import add_repository_to_vectorstore
        add_repository_to_vectorstore(repo_data)
        
        return {
            "status": "success",
            "project_id": project_id,
            "project_name": repo_data["project_name"],
            "files_ingested": len(repo_data["files"]),
            "files": [
                {
                    "path": f["path"],
                    "content": f.get("content", ""),
                    "functions": [fn["name"] for fn in f.get("functions", [])]
                }
                for f in repo_data["files"]
            ]
        }
    except HTTPException:
        # Clean up on failure
        shutil.rmtree(upload_dir, ignore_errors=True)
        raise
    except Exception as e:
        # Clean up on failure
        shutil.rmtree(upload_dir, ignore_errors=True)
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/ingest")
async def ingest_repo(
    req: RepositoryRequest,
    current_user: dict = Depends(require_role(["ADMIN"]))
) -> Dict[str, Any]:
    """
    Ingests a repository from the specified path.
    """
    if not os.path.exists(req.repo_path):
        raise HTTPException(status_code=404, detail="Repository path not found")
        
    try:
        project_id = str(uuid.uuid4())
        project_name = os.path.basename(os.path.abspath(req.repo_path))
        
        repo_data = ingest_repository(req.repo_path, project_name=project_name, project_id=project_id)
        
        # Add to RAG
        from ..vectorstore.index import add_repository_to_vectorstore
        add_repository_to_vectorstore(repo_data)
        
        return {
            "status": "success",
            "project_id": project_id,
            "project_name": repo_data["project_name"],
            "repo_path": repo_data["path"],
            "git_info": repo_data["git_info"],
            "files_ingested": len(repo_data["files"]),
            "files": [
                {
                    "path": f["path"],
                    "functions": [fn["name"] for fn in f.get("functions", [])]
                }
                for f in repo_data["files"]
            ]
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
