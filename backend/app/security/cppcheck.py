import subprocess
import os
import re
import shutil
from typing import List, Dict, Optional


def _find_include_dirs(repo_path: str) -> List[str]:
    """
    Walk the repository and collect every directory that contains at least one
    header file (.h / .hpp).  These directories are passed to Cppcheck via -I
    so that project-local ``#include "…"`` directives can be resolved.
    """
    include_dirs: set[str] = set()
    for root, _dirs, files in os.walk(repo_path):
        for f in files:
            if f.endswith((".h", ".hpp")):
                include_dirs.add(root)
                break  # one header is enough to mark this directory
    return sorted(include_dirs)


def _collect_project_headers(repo_path: str) -> Dict[str, str]:
    """
    Return a mapping  {header_basename: absolute_path}  for every header file
    found in the repository.  When a basename appears in multiple directories
    the first one found (top-down walk) wins — this mirrors typical compiler
    search-path behaviour.
    """
    headers: Dict[str, str] = {}
    for root, _dirs, files in os.walk(repo_path):
        for f in files:
            if f.endswith((".h", ".hpp")) and f not in headers:
                headers[f] = os.path.join(root, f)
    return headers


def _extract_local_includes(code: str) -> List[str]:
    """
    Parse ``#include "header.h"`` directives (project-local includes only).
    System includes (angle-brackets) are intentionally ignored.
    """
    return re.findall(r'#include\s+"([^"]+)"', code)


# ─── Repository-level analysis ──────────────────────────────────────────────


def run_cppcheck(repo_path: str) -> List[Dict]:
    """
    Runs cppcheck against the full repository, automatically discovering
    project include directories.  Fails gracefully if cppcheck is not
    installed.
    """
    if not os.path.exists(repo_path):
        return []

    try:
        cmd = [
            "cppcheck",
            "--enable=all",
            "--xml",
            "--inconclusive",
            "--suppress=missingIncludeSystem",
        ]

        # Add every directory that contains a header as an include path
        for inc_dir in _find_include_dirs(repo_path):
            cmd.extend(["-I", inc_dir])

        cmd.append(".")

        result = subprocess.run(cmd, cwd=repo_path, capture_output=True, text=True)

        # cppcheck outputs XML to stderr
        xml_output = result.stderr

        if not xml_output or "<?xml" not in xml_output:
            return []

        return parse_cppcheck_xml(xml_output, repo_path)

    except FileNotFoundError:
        # cppcheck is not installed
        print(
            "cppcheck is not installed. AI/static pattern analysis is still available."
        )
        return []
    except Exception as e:
        print(f"Error running cppcheck: {e}")
        return []


# ─── Helpers: severity / category mapping ────────────────────────────────────


def map_cppcheck_category(rule_id: str) -> str:
    rule_id = rule_id.lower()
    if "uninit" in rule_id:
        return "UNINITIALIZED_VARIABLE"
    elif "outofbounds" in rule_id or "arrayindex" in rule_id:
        return "OUT_OF_BOUNDS"
    elif "zerodiv" in rule_id:
        return "DIVISION_BY_ZERO"
    elif "overflow" in rule_id or "shift" in rule_id:
        return "INTEGER_OVERFLOW"
    elif "nullpointer" in rule_id:
        return "NULL_POINTER"
    elif "buffer" in rule_id:
        return "BUFFER_OVERFLOW"
    elif "leak" in rule_id or "free" in rule_id or "autovariable" in rule_id:
        return "MEMORY_ERROR"
    elif "misra" in rule_id:
        return "MISRA"
    elif "str" in rule_id:
        return "UNSAFE_STRING_OPS"
    else:
        return "STATIC_ANALYSIS"


def map_cppcheck_severity(rule_id: str, severity: str) -> str:
    """Map Cppcheck diagnostics to the application's normalized severity."""
    if rule_id.lower() in {"missinginclude", "missingincludesystem"}:
        return "INFO"

    return {
        "error": "HIGH",
        "warning": "MEDIUM",
        "style": "LOW",
        "performance": "LOW",
        "portability": "LOW",
        "information": "INFO",
    }.get(severity, "INFO")


# ─── XML parser ──────────────────────────────────────────────────────────────


def parse_cppcheck_xml(xml_content: str, repo_path: str) -> List[Dict]:
    import xml.etree.ElementTree as ET

    findings = []
    try:
        root = ET.fromstring(xml_content)
        errors = root.find("errors")
        if errors is None:
            return findings

        for error in errors.findall("error"):
            msg = error.get("msg", "")
            severity = error.get("severity", "style")
            rule_id = error.get("id", "")

            # Map cppcheck severity to our scale
            mapped_severity = map_cppcheck_severity(rule_id, severity)
            category = map_cppcheck_category(rule_id)

            for location in error.findall("location"):
                file_path = location.get("file", "")
                line_num = int(location.get("line", 0))

                findings.append(
                    {
                        "file": file_path,
                        "line": line_num,
                        "severity": mapped_severity,
                        "message": msg,
                        "rule": rule_id,
                        "source": "cppcheck",
                        "category": category,
                    }
                )
    except Exception as e:
        print(f"Failed to parse cppcheck XML: {e}")

    return findings


# ─── Repository-aware single-file analysis ───────────────────────────────────


def run_cppcheck_on_repo_file(
    repo_path: str,
    file_path: str,
    language: str = "c",
) -> List[Dict]:
    """
    Run Cppcheck on a single file *within* a repository.  The repo's include
    directories are passed via ``-I`` so that project headers resolve correctly.

    Parameters
    ----------
    repo_path : str
        Absolute path to the repository root on disk.
    file_path : str
        Relative path of the source file inside ``repo_path``
        (e.g. ``"src/main.c"``).
    language : str
        ``"c"`` or ``"cpp"`` — forwarded to Cppcheck via ``--language=``.

    Returns
    -------
    list[dict]
        Formatted findings suitable for the analysis pipeline.
    """
    abs_file = os.path.join(repo_path, file_path)
    if not os.path.isfile(abs_file):
        return []

    try:
        cmd = [
            "cppcheck",
            "--enable=all",
            "--xml",
            "--inconclusive",
            "--suppress=missingIncludeSystem",
            f"--language={language}",
        ]

        for inc_dir in _find_include_dirs(repo_path):
            cmd.extend(["-I", inc_dir])

        cmd.append(abs_file)

        result = subprocess.run(
            cmd,
            cwd=repo_path,
            capture_output=True,
            text=True,
        )

        xml_output = result.stderr
        if not xml_output or "<?xml" not in xml_output:
            return []

        raw_findings = parse_cppcheck_xml(xml_output, repo_path)

        # Read source for line-content lookup
        with open(abs_file, "r", encoding="utf-8", errors="replace") as fh:
            lines = fh.read().splitlines()

        formatted: List[Dict] = []
        for finding in raw_findings:
            line_num = finding.get("line", 1)
            line_content = lines[line_num - 1] if 0 < line_num <= len(lines) else ""

            formatted.append(
                {
                    "type": finding.get("rule", "CPPCHECK_ISSUE"),
                    "severity": finding.get("severity", "LOW"),
                    "category": finding.get("category", "STATIC_ANALYSIS"),
                    "line": line_num,
                    "code": line_content.strip(),
                    "description": finding.get("message", ""),
                    "source": "CPPCHECK",
                }
            )

        return formatted

    except FileNotFoundError:
        print("[WARNING] Cppcheck is not installed or not in PATH.")
        raise RuntimeError("Static-analysis tooling (cppcheck) is unavailable.")
    except Exception as e:
        print(f"Error running cppcheck on repo file: {e}")
        return []


# ─── Standalone code-snippet analysis (improved) ─────────────────────────────


def run_cppcheck_on_code(
    code: str,
    language: str = "c",
    repo_path: Optional[str] = None,
    file_path: Optional[str] = None,
) -> List[Dict]:
    """
    Run Cppcheck on a code snippet.

    **Repository-aware mode** (``repo_path`` is set):
        If the file exists on disk inside the repository, Cppcheck runs against
        the real file with proper include paths — giving it full header context.

    **Standalone mode** (no ``repo_path``):
        The code is written to a temporary directory.  Any project-local
        ``#include "…"`` headers found in the repository (if ``repo_path`` is
        provided) are copied alongside the temp file so Cppcheck can resolve
        them.  System-header missing-include diagnostics are suppressed because
        Cppcheck does not need them for useful analysis.
    """
    import tempfile

    # ── Fast-path: analyse the real file in the repository ──────────────
    if repo_path and file_path:
        abs_file = os.path.join(repo_path, file_path)
        if os.path.isfile(abs_file):
            return run_cppcheck_on_repo_file(repo_path, file_path, language)

    # ── Slow-path: build a temporary workspace ──────────────────────────
    ext = ".cpp" if language == "cpp" else ".c"
    tmp_dir = tempfile.mkdtemp(prefix="cppcheck_")

    try:
        # Write the source file
        src_path = os.path.join(tmp_dir, f"analysis{ext}")
        with open(src_path, "w", encoding="utf-8") as f:
            f.write(code)

        # Copy project headers into the temp workspace so Cppcheck can
        # resolve ``#include "header.h"`` directives.
        include_dirs: List[str] = []
        if repo_path and os.path.isdir(repo_path):
            needed_headers = _extract_local_includes(code)
            available_headers = _collect_project_headers(repo_path)

            for hdr_name in needed_headers:
                # hdr_name could be a bare name ("utils.h") or a relative
                # path ("lib/utils.h").
                basename = os.path.basename(hdr_name)
                src_hdr = available_headers.get(basename)
                if src_hdr and os.path.isfile(src_hdr):
                    # Preserve relative directory structure inside tmp_dir
                    dest = os.path.join(tmp_dir, hdr_name)
                    os.makedirs(os.path.dirname(dest), exist_ok=True)
                    shutil.copy2(src_hdr, dest)

            # Also pass the repo's own include dirs so nested includes within
            # copied headers can resolve.
            include_dirs = _find_include_dirs(repo_path)

        # Build the Cppcheck command
        cmd = [
            "cppcheck",
            "--enable=all",
            "--xml",
            "--inconclusive",
            "--suppress=missingIncludeSystem",
            f"--language={language}",
        ]

        # Always include the temp dir itself (where we placed the headers)
        cmd.extend(["-I", tmp_dir])

        for inc_dir in include_dirs:
            cmd.extend(["-I", inc_dir])

        cmd.append(src_path)

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
        )

        xml_output = result.stderr
        if not xml_output or "<?xml" not in xml_output:
            return []

        findings = parse_cppcheck_xml(xml_output, tmp_dir)

        # Map temp-file findings back to the original code
        lines = code.splitlines()

        formatted_findings: List[Dict] = []
        for finding in findings:
            line_num = finding.get("line", 1)
            line_content = lines[line_num - 1] if 0 < line_num <= len(lines) else ""

            formatted_findings.append(
                {
                    "type": finding.get("rule", "CPPCHECK_ISSUE"),
                    "severity": finding.get("severity", "LOW"),
                    "category": finding.get("category", "STATIC_ANALYSIS"),
                    "line": line_num,
                    "code": line_content.strip(),
                    "description": finding.get("message", ""),
                    "source": "CPPCHECK",
                }
            )

        return formatted_findings

    except FileNotFoundError:
        print("[WARNING] Cppcheck is not installed or not in PATH.")
        raise RuntimeError("Static-analysis tooling (cppcheck) is unavailable.")
    except Exception as e:
        print(f"Error running cppcheck on code: {e}")
        return []
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)
