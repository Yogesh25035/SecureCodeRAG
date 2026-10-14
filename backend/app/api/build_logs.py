from fastapi import APIRouter, HTTPException, UploadFile, File, Form, Depends
from typing import Dict, Any, Optional
from app.core.auth import get_current_user, verify_project_access

from app.security.compiler_logs import parse_compiler_logs, associate_warnings_with_repo
from app.security.confidence import calculate_confidence
from app.core.config import settings

router = APIRouter()

MAX_LOG_SIZE = 10 * 1024 * 1024  # 10 MB


@router.post("/upload", tags=["build-log"])
async def upload_build_log(
    file: UploadFile = File(...),
    project_id: Optional[str] = Form(default=None),
    current_user: dict = Depends(get_current_user)
) -> Dict[str, Any]:
    """
    Upload a compiler/build log file.

    Parses warnings from GCC, Clang, MSVC, IAR, Make, or Cppcheck text format.
    Associates warnings with repository files when repo_id is provided.
    Optionally uses the LLM to generate evidence-grounded explanations.
    """
    if project_id:
        verify_project_access(current_user, project_id)

    # ----------------------------------------------------------------
    # 1. Validate file
    # ----------------------------------------------------------------
    if not file.filename:
        raise HTTPException(status_code=400, detail="No filename provided")

    allowed_exts = {".log", ".txt", ".out", ".err", ".build"}
    ext = "." + file.filename.rsplit(".", 1)[-1].lower() if "." in file.filename else ""
    if ext not in allowed_exts:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported file type '{ext}'. Allowed: {allowed_exts}"
        )

    raw_bytes = await file.read()
    if len(raw_bytes) > MAX_LOG_SIZE:
        raise HTTPException(status_code=413, detail="Log file exceeds 10 MB limit")

    try:
        log_content = raw_bytes.decode("utf-8", errors="replace")
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Could not decode log file: {e}")

    # ----------------------------------------------------------------
    # 2. Parse all warnings
    # ----------------------------------------------------------------
    warnings = parse_compiler_logs(log_content)

    if not warnings:
        return {
            "status": "ok",
            "warnings_found": 0,
            "findings": [],
            "message": "No parseable compiler warnings found in the log."
        }

    # ----------------------------------------------------------------
    # 3. Associate with repo files (if repo_id supplied)
    # ----------------------------------------------------------------
    repo_data = None
    if project_id:
        try:
            from app.repository.manager import ingest_repository
            import os
            from app.api.repositories import _get_repo_path_by_id  # optional helper
            # Attempt to load repo content for association
            repo_path = _get_repo_path_by_id(project_id)
            if repo_path and os.path.exists(repo_path):
                repo_data = ingest_repository(repo_path, project_id=project_id)
        except Exception:
            pass  # Gracefully continue without repo association

    warnings = associate_warnings_with_repo(warnings, repo_data)

    # ----------------------------------------------------------------
    # 4. Generate LLM explanations (if provider configured)
    # ----------------------------------------------------------------
    provider = settings.LLM_PROVIDER.lower()
    retriever = None
    llm = None
    rag_prompt = None

    if provider != "dummy":
        try:
            from app.rag.retriever import VulnerabilityRetriever
            from app.core.llm import get_llm
            from app.rag.prompts import COMPILER_EXPLANATION_PROMPT

            retriever = VulnerabilityRetriever()
            llm = get_llm()
            rag_prompt = COMPILER_EXPLANATION_PROMPT
        except Exception as e:
            print(f"[WARNING] LLM/RAG init failed for build log: {e}")

    findings = []
    for w in warnings:
        explanation = (
            f"Compiler finding: {w.get('message', '')}. "
            "Configure LLM_PROVIDER for AI-generated explanation."
        )
        confidence = calculate_confidence(
            {"type": "COMPILER_WARNING", "severity": w.get("severity", "MEDIUM")},
            []
        )

        # AI explanation using compiler-specific prompt
        if llm and rag_prompt:
            try:
                rag_query = f"compiler warning {w.get('code', '')} {w.get('message', '')}"
                context_docs = []
                if retriever:
                    context_docs = retriever.retrieve(
                        rag_query,
                        top_k=2,
                        project_id=project_id
                    )

                context = "\n\n".join(
                    doc.page_content.strip()
                    for doc in context_docs[:2]
                    if hasattr(doc, "page_content") and doc.page_content.strip()
                ) or "No specific guidance retrieved."

                prompt = rag_prompt.format(
                    file_path=w.get("file_path", w.get("file", "unknown")),
                    line_num=w.get("line", "unknown"),
                    severity=w.get("severity", "unknown"),
                    warning_code=w.get("code", "N/A"),
                    compiler_message=w.get("message", ""),
                    source=w.get("source", "COMPILER"),
                    code_snippet=w.get("code_snippet", w.get("code", "Not available")),
                    context=context
                )

                response = llm.invoke(prompt)
                explanation = (
                    response.content.strip()
                    if hasattr(response, "content")
                    else str(response).strip()
                )

                # Recalculate with evidence docs
                confidence = calculate_confidence(
                    {"type": "COMPILER_WARNING", "severity": w.get("severity", "MEDIUM")},
                    context_docs
                )
            except Exception as e:
                print(f"[WARNING] LLM explanation failed: {e}")

        findings.append({
            "type": "COMPILER_WARNING",
            "severity": w.get("severity", "MEDIUM"),
            "file": w.get("file_path", w.get("file", "unknown")),
            "line": w.get("line", 0),
            "code": w.get("code", ""),
            "warning_code": w.get("code", "N/A"),
            "message": w.get("message", ""),
            "source": "COMPILER",
            "repo_found": w.get("repo_found", False),
            "explanation": explanation,
            "confidence": confidence,
        })

    return {
        "status": "ok",
        "warnings_found": len(findings),
        "project_id": project_id,
        "findings": findings,
    }


def _get_repo_path_by_id(project_id: str):
    """Resolve a repo_id back to its disk path inside data/repos."""
    import os
    base = os.path.join(
        os.path.dirname(__file__), "..", "data", "repos", project_id
    )
    return os.path.normpath(base) if os.path.exists(base) else None
