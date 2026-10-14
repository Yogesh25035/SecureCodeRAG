import os
import hashlib
from .parser import get_file_type, parse_c_file
from .git import get_repo_info

IGNORE_DIRS = {'.git', 'node_modules', 'build', 'dist', 'venv', '__pycache__', 'binaries'}
MAX_FILE_SIZE = 5 * 1024 * 1024 # 5 MB

def get_file_hash(filepath):
    hash_md5 = hashlib.md5()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()

def ingest_repository(repo_path: str, project_name: str = "unknown", project_id: str = "unknown"):
    """
    Ingests a repository from a given path with strict validations.
    """
    if not os.path.exists(repo_path):
        raise ValueError(f"Path does not exist: {repo_path}")
        
    repo_data = {
        "project_id": project_id,
        "project_name": project_name,
        "path": repo_path,
        "files": [],
        "git_info": get_repo_info(repo_path)
    }
    
    seen_hashes = set()
    
    for root, dirs, files in os.walk(repo_path):
        # Prune ignored directories
        dirs[:] = [d for d in dirs if d not in IGNORE_DIRS and "generated" not in d.lower()]
        
        for file in files:
            full_path = os.path.join(root, file)
            rel_path = os.path.relpath(full_path, repo_path)
            file_type = get_file_type(file)
            
            if file_type not in ('c_cpp', 'header'):
                continue
                
            try:
                # File size validation
                size = os.path.getsize(full_path)
                if size > MAX_FILE_SIZE:
                    continue
                    
                # Content hash / Duplicate check
                file_hash = get_file_hash(full_path)
                if file_hash in seen_hashes:
                    continue
                seen_hashes.add(file_hash)
                
                try:
                    with open(full_path, 'r', encoding='utf-8') as f:
                        content = f.read()
                    if '\0' in content:
                        continue
                except UnicodeDecodeError:
                    continue
                
                parsed = parse_c_file(content)
                extension = os.path.splitext(file)[1]
                
                repo_data["files"].append({
                    "path": rel_path,
                    "type": file_type,
                    "extension": extension,
                    "size": size,
                    "hash": file_hash,
                    "content": content,
                    "functions": parsed.get("functions", []),
                    "includes": parsed.get("includes", []),
                    "dependencies": parsed.get("dependencies", []),
                    "declarations": parsed.get("declarations", []),
                    "symbols": parsed.get("symbols", [])
                })
            except Exception as e:
                print(f"Failed to read {full_path}: {e}")
                
    return repo_data
