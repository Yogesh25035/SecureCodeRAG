from pydantic import BaseModel, Field
from typing import Optional

class CodeRequest(BaseModel):
    code: str = Field(..., description="Source code to analyze for vulnerabilities")
    language: str = Field(default="python", description="Programming language")
    file_path: Optional[str] = Field(default=None, description="Source file path for finding attribution")
    repo_version: Optional[str] = Field(default="HEAD", description="Repository version or commit hash")
    project_id: Optional[str] = Field(default=None, description="Optional repository ID to scope RAG context")
    compiler_logs: Optional[str] = Field(default=None, description="Optional compiler build logs to analyze alongside source code")
    
    class Config:
        json_schema_extra = {
            "example": {
                "code": "query = f\"SELECT * FROM users WHERE id={user_id}\"",
                "language": "python",
                "file_path": "src/main.py",
                "project_id": "optional-uuid-here"
            }
        }

class RepositoryRequest(BaseModel):
    repo_path: str = Field(..., description="Absolute or relative path to the repository on disk")
    
    class Config:
        json_schema_extra = {
            "example": {
                "repo_path": "/data/demo_repository"
            }
        }
