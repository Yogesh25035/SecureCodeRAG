from app.core.config import settings

def calculate_confidence(vulnerability: dict, context_docs: list) -> float:
    """
    Calculate confidence score based on static evidence and RAG context.
    Phase 9: Confidence calculation should remain deterministic and not rely
    on arbitrary LLM blending.
    
    LIMITATION: This confidence score is a heuristic weighting based on rule 
    specificity (e.g., regex vs AST vs combined) and is not statistically calibrated.
    """
    source = vulnerability.get("source", "regex").lower()
    
    # Calculate confidence from evidence rather than arbitrary LLM agreement.
    # Distinguish Detection confidence from Explanation quality.
    if source in ("combined", "multiple"):
        base_score = 0.98  # Multiple sources agree -> High detection confidence
    elif source == "cppcheck":
        base_score = 0.90
    elif source == "compiler":
        base_score = 0.95
    else:
        # Regex static scanner
        vuln_type = vulnerability.get("type", "")
        if vuln_type in ("NULL_POINTER", "UNSAFE_STRING_OPS", "BOUNDARY_VIOLATION"):
            base_score = 0.85
        else:
            base_score = 0.65
        
    # Modifier for severity confidence
    severity = str(vulnerability.get('severity', '')).upper()
    if severity == 'CRITICAL':
        base_score += 0.05
    elif severity == 'HIGH':
        base_score += 0.02
        
    # RAG evidence modifier
    rag_modifier = 0.08 if (context_docs and len(context_docs) > 0) else 0.0
    
    # Calculate final score
    final_score = base_score + rag_modifier
    
    return round(min(max(final_score, 0.0), 1.0), 2)
