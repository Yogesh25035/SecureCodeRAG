from pydantic import BaseModel, Field
from typing import Optional
from enum import Enum

class SeverityEnum(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

class FindingStatus(str, Enum):
    PENDING_REVIEW = "PENDING_REVIEW"
    ACCEPTED = "ACCEPTED"
    EDITED = "EDITED"
    REJECTED = "REJECTED"

class StructuredFinding(BaseModel):
    finding_id: str
    project_id: str
    file: str
    function: Optional[str] = None
    line_start: int
    line_end: Optional[int] = None
    severity: SeverityEnum
    category: str
    title: str
    finding: str
    evidence: str
    root_cause: Optional[str] = None
    rule: Optional[str] = None
    source: str
    confidence: float
    diagnostic_message: Optional[str] = None
    evidence_status: str = "INSUFFICIENT_CONTEXT"
    explanation_quality: Optional[float] = None
    recommendation: Optional[str] = None
    suggested_fix: Optional[str] = None
    status: FindingStatus = FindingStatus.PENDING_REVIEW
