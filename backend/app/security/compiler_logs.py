import re
import os
from typing import List, Dict, Optional


# ------------------------------------------------------------------
# Severity mappings
# ------------------------------------------------------------------

_GCC_SEVERITY_MAP = {
    "warning": "MEDIUM",
    "error": "HIGH",
    "fatal error": "CRITICAL",
    "note": "INFO",
}

_MSVC_SEVERITY_MAP = {
    "warning": "MEDIUM",
    "error": "HIGH",
    "fatal error": "CRITICAL",
    "note": "INFO",
}


# ------------------------------------------------------------------
# Format patterns
# ------------------------------------------------------------------

# GCC/Clang:  file.c:10:3: warning: message [-Wformat]
_GCC_PATTERN = re.compile(
    r'^(?P<file>[^:]+):(?P<line>\d+):(?:\d+:)?\s*'
    r'(?P<severity>warning|error|fatal error|note):\s*'
    r'(?P<message>[^\[]+)'
    r'(?:\[(?P<code>[^\]]+)\])?',
    re.IGNORECASE,
)

# MSVC:  file.c(10): warning C4101: message
_MSVC_PATTERN = re.compile(
    r'^(?P<file>[^(]+)\((?P<line>\d+)\):\s*'
    r'(?P<severity>warning|error|fatal error|note)\s+'
    r'(?P<code>[A-Z]\d+):\s*'
    r'(?P<message>.+)',
    re.IGNORECASE,
)

# IAR:  "file.c",10  Warning[Pa082]: message
_IAR_PATTERN = re.compile(
    r'^"(?P<file>[^"]+)",(?P<line>\d+)\s+'
    r'(?P<severity>Warning|Error|Fatal)\[(?P<code>[^\]]+)\]:\s*'
    r'(?P<message>.+)',
    re.IGNORECASE,
)

# Make / generic error reference:  make[1]: *** [file.c:10] Error 1
_MAKE_ERROR_PATTERN = re.compile(
    r'make.*:\s+\*+\s+\[(?P<file>[^:]+):(?P<line>\d+)\]\s+Error\s+(?P<code>\d+)',
    re.IGNORECASE,
)

# Cppcheck XML-style inline messages (text form):
#   [file.c:10]: (error) message  [ruleId]
_CPPCHECK_TEXT_PATTERN = re.compile(
    r'^\[(?P<file>[^:]+):(?P<line>\d+)\]:\s+'
    r'\((?P<severity>\w+)\)\s+'
    r'(?P<message>[^\[]+)'
    r'(?:\[(?P<code>[^\]]+)\])?',
)


def _map_severity(raw: str, table: dict) -> str:
    return table.get(raw.strip().lower(), "INFO")


def _try_patterns(line: str) -> Optional[Dict]:
    """Try each known format in order; return first match."""

    for pattern, sev_table in [
        (_GCC_PATTERN, _GCC_SEVERITY_MAP),
        (_MSVC_PATTERN, _MSVC_SEVERITY_MAP),
        (_IAR_PATTERN, _GCC_SEVERITY_MAP),
        (_CPPCHECK_TEXT_PATTERN, _GCC_SEVERITY_MAP),
    ]:
        m = pattern.match(line.strip())
        if m:
            return {
                "file":     m.group("file").strip(),
                "line":     int(m.group("line")),
                "severity": _map_severity(m.group("severity"), sev_table),
                "message":  m.group("message").strip(),
                "code":     (m.group("code") or "").strip(),
                "source":   "COMPILER",
                "category": "COMPILER_WARNING",
                "type":     "COMPILER_WARNING",
            }

    # Make error (no message text available)
    m = _MAKE_ERROR_PATTERN.match(line.strip())
    if m:
        return {
            "file":     m.group("file").strip(),
            "line":     int(m.group("line")),
            "severity": "HIGH",
            "message":  f"Build error {m.group('code')}",
            "code":     f"MAKE_ERR_{m.group('code')}",
            "source":   "COMPILER",
            "category": "COMPILER_WARNING",
            "type":     "COMPILER_WARNING",
        }

    return None


def parse_compiler_logs(log_content: str) -> List[Dict]:
    """
    Parse compiler/build logs from GCC, Clang, MSVC, IAR, Make, or Cppcheck
    text format. Returns a list of structured findings.
    """
    findings = []
    seen = set()

    for raw_line in log_content.splitlines():
        result = _try_patterns(raw_line)
        if not result:
            continue

        # Dedup key
        key = (result["file"], result["line"], result["message"][:80])
        if key in seen:
            continue
        seen.add(key)

        findings.append(result)

    return findings


def associate_warnings_with_repo(
    warnings: List[Dict],
    repo_data: Optional[Dict],
) -> List[Dict]:
    """
    For each compiler warning, try to locate the corresponding
    source file inside an already-ingested repository.

    Adds:
        - `file_path` (absolute/relative repo path if found)
        - `code`      (line content from source file)
        - `repo_found` (bool)
    """
    if not repo_data:
        for w in warnings:
            w["repo_found"] = False
        return warnings

    # Build a fast lookup: basename → full repo file dict
    repo_index: Dict[str, Dict] = {}
    for f in repo_data.get("files", []):
        basename = os.path.basename(f["path"]).lower()
        repo_index[basename] = f
        # Also index by partial relative path
        repo_index[f["path"].lower()] = f

    for warning in warnings:
        warn_file = warning.get("file", "")
        warn_basename = os.path.basename(warn_file).lower()
        warn_rel = warn_file.lower().replace("\\", "/")

        matched_file = (
            repo_index.get(warn_basename)
            or repo_index.get(warn_rel)
        )

        if matched_file:
            warning["repo_found"] = True
            warning["file_path"] = matched_file["path"]

            # Extract the exact source line for evidence
            content_lines = matched_file.get("content", "").splitlines()
            line_idx = warning["line"] - 1
            if 0 <= line_idx < len(content_lines):
                warning["code"] = content_lines[line_idx].strip()
            else:
                warning["code"] = ""
        else:
            warning["repo_found"] = False
            warning["file_path"] = warn_file
            warning["code"] = ""

    return warnings

