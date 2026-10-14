"""Automotive C/C++ Vulnerability detection patterns for static analysis"""

AUTOMOTIVE_PATTERNS = {
    "NULL_POINTER": {
        "pattern": r"\*\w+|->\w+", 
        "severity": "HIGH",
        "category": "NULL_POINTER",
        "description": "Potential null pointer dereference."
    },
    "BOUNDARY_VIOLATION": {
        "pattern": r"\w+\[\w+\]",
        "severity": "HIGH",
        "category": "BOUNDARY_VIOLATION",
        "description": "Array access may exceed the valid boundary."
    },
    "UNSAFE_STRING_OPS": {
        "pattern": r"\b(strcpy|strcat|sprintf|gets)\b",
        "severity": "CRITICAL",
        "category": "UNSAFE_STRING_OPS",
        "description": "Use of inherently unsafe C standard library functions (e.g. strcpy, gets)."
    },
    "RESOURCE_MISMANAGEMENT": {
        "pattern": r"\b(malloc|calloc|realloc|free)\b",
        "severity": "MEDIUM",
        "category": "RESOURCE_MISMANAGEMENT",
        "description": "Manual memory management without explicit bounds/lifetime tracking poses risks."
    },
    "UNSAFE_TYPE_CONVERSION": {
        "pattern": r"\(\s*(int|short|char|long|float|double)\s*\)\s*\w+",
        "severity": "LOW",
        "category": "UNSAFE_TYPE_CONVERSION",
        "description": "Explicit type conversion may reduce type safety."
    },
    "MISSING_INPUT_VALIDATION": {
        "pattern": r"\b(scanf|fscanf|sscanf|read)\b",
        "severity": "HIGH",
        "category": "MISSING_INPUT_VALIDATION",
        "description": "External input read without apparent immediate size/boundary validation."
    },
    "INTEGER_OVERFLOW": {
        "pattern": r"(?:\b(?!char\b|int\b|long\b|short\b|float\b|double\b|void\b)[a-zA-Z_]\w*\s*[\*\+]\s*(?:[a-zA-Z_]\w*|\d+))|(?:\b[a-zA-Z_]\w*\s*/\s*-1\b)",
        "severity": "MEDIUM",
        "category": "INTEGER_OVERFLOW",
        "description": "Potential integer overflow or invalid signed division (e.g. INT_MIN / -1)."
    }
}
