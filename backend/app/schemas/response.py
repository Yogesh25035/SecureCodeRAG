from pydantic import BaseModel
from typing import List, Optional

class Vulnerability(BaseModel):
    type: str
    severity: str
    line: int
    code: str
    explanation: str
    confidence: float
    function_name: Optional[str] = None
    source: str = "PROJECT_RULE"

from app.schemas.findings import StructuredFinding

class AnalysisResponse(BaseModel):
    vulnerabilities: List[StructuredFinding]
    total_vulnerabilities: int
    summary: Optional[str] = None
    status: str = "SUCCESS"
    warnings: List[str] = []
    
    class Config:
        json_schema_extra = {
            "example": {
                "vulnerabilities": [
                    {
                        "type": "SQL Injection",
                        "severity": "high",
                        "line": 1,
                        "code": "query = f\"SELECT * FROM users WHERE id={user_id}\"",
                        "explanation": "This code is vulnerable to SQL injection...",
                        "confidence": 0.95
                    }
                ],
                "total_vulnerabilities": 1,
                "summary": "Found 1 high severity vulnerability"
            }
        }
