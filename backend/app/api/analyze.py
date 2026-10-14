from fastapi import APIRouter, Depends
from app.core.auth import get_current_user, verify_project_access

from app.schemas.request import CodeRequest
from app.schemas.response import AnalysisResponse
from app.schemas.findings import StructuredFinding, SeverityEnum

from app.security.static_scan import StaticScanner
from app.security.confidence import calculate_confidence
from app.security.code_context import get_code_context
from app.core.config import settings
import os
import uuid

router = APIRouter()
scanner = StaticScanner()


@router.post("/analyze", response_model=AnalysisResponse)
async def analyze_code(
    request: CodeRequest, current_user: dict = Depends(get_current_user)
):
    if request.project_id:
        verify_project_access(current_user, request.project_id)
    from app.repository.parser import parse_c_file
    from app.security.compiler_logs import parse_compiler_logs

    warnings = []
    parsed_struct = None
    if request.language in ("c", "cpp"):
        try:
            parsed_struct = parse_c_file(request.code)
        except Exception as e:
            print(f"[WARNING] Parsing failed: {e}")

    # 1. Project static scanner
    vulnerabilities = scanner.scan(request.code)

    # 2. Cppcheck Integration — repository-aware when project_id is available
    from app.security.cppcheck import run_cppcheck_on_code

    if request.language in ("c", "cpp"):
        try:
            # Resolve the on-disk repository path from project_id so that
            # Cppcheck can locate project headers via -I include paths.
            repo_path = None
            if request.project_id:
                candidate = os.path.join(
                    os.path.dirname(__file__), "..", "data", "repos", request.project_id
                )
                if os.path.isdir(candidate):
                    repo_path = os.path.abspath(candidate)

            cppcheck_findings = run_cppcheck_on_code(
                request.code,
                request.language,
                repo_path=repo_path,
                file_path=request.file_path,
            )
            vulnerabilities.extend(cppcheck_findings)
        except Exception as e:
            print(f"[WARNING] Cppcheck failed: {e}")
            warnings.append(str(e))

    # 3. Compiler logs
    if request.compiler_logs:
        comp_vulns = parse_compiler_logs(request.compiler_logs)
        for w in comp_vulns:
            line_idx = w["line"] - 1
            lines = request.code.splitlines()
            w["code"] = lines[line_idx].strip() if 0 <= line_idx < len(lines) else ""
        vulnerabilities.extend(comp_vulns)

    # Deduplicate and add supporting evidence
    vulnerabilities = scanner._deduplicate(vulnerabilities)
    vulnerabilities.sort(key=lambda x: x.get("line", 0))

    # 4. Repository structural analysis
    if parsed_struct and "functions" in parsed_struct:
        for vuln in vulnerabilities:
            v_line = vuln.get("line", 0)
            for f in parsed_struct["functions"]:
                if f.get("start_line", 0) <= v_line <= f.get("end_line", 0):
                    vuln["function_name"] = f["name"]
                    break

    results = []
    provider = settings.LLM_PROVIDER.lower()

    retriever = None
    generator = None

    if provider != "dummy":
        try:
            from app.rag.retriever import VulnerabilityRetriever
            from app.rag.generator import ExplanationGenerator

            retriever = VulnerabilityRetriever(
                project_id=getattr(request, "project_id", None)
            )
            generator = ExplanationGenerator()
        except Exception as e:
            print(f"[WARNING] RAG/LLM initialization failed: {e}")

    for vuln in vulnerabilities:
        context_docs = []
        explanation = (
            "Static analysis finding. Configure LLM_PROVIDER for AI explanation."
        )
        explanation_quality = 0.0
        diagnostic_rule = str(vuln.get("type") or "").lower()
        is_missing_include = diagnostic_rule in {
            "missinginclude",
            "missingincludesystem",
        }

        confidence = calculate_confidence(vuln, context_docs)

        if is_missing_include:
            from app.rag.generator import build_missing_include_explanation

            explanation = build_missing_include_explanation(vuln)
        elif retriever and generator:
            try:
                category = vuln.get("category") or vuln.get("type") or "UNKNOWN"
                rag_query = (
                    f"{category} {vuln.get('code', '')} {vuln.get('description', '')}"
                )

                context_docs = retriever.retrieve(
                    rag_query, top_k=2, project_id=getattr(request, "project_id", None)
                )

                func_start = None
                func_end = None
                if parsed_struct and "functions" in parsed_struct:
                    v_line = vuln.get("line", 0)
                    for f in parsed_struct["functions"]:
                        if f.get("start_line", 0) <= v_line <= f.get("end_line", 0):
                            func_start = f["start_line"]
                            func_end = f["end_line"]
                            break

                context_snippet = get_code_context(
                    request.code,
                    vuln.get("line"),
                    func_start=func_start,
                    func_end=func_end,
                )
                vuln_with_context = vuln.copy()
                if context_snippet:
                    vuln_with_context["code"] = context_snippet

                explanation = generator.generate_explanation(
                    vuln_with_context, context_docs
                )

                confidence = calculate_confidence(vuln, context_docs)

                if "Evidence Status: CONFIRMED" in explanation:
                    explanation_quality = 1.0
                elif "Evidence Status: LIKELY" in explanation:
                    explanation_quality = 0.8
                elif "Evidence Status: INSUFFICIENT_CONTEXT" in explanation:
                    explanation_quality = 0.4
                else:
                    explanation_quality = 0.6

            except Exception as e:
                print(f"[WARNING] AI explanation failed: {e}")
                explanation = "AI explanation unavailable. The deterministic finding remains valid."
                explanation_quality = 0.0
                if "AI explanation failed or produced invalid output." not in warnings:
                    warnings.append("AI explanation failed or produced invalid output.")

        sev_str = str(vuln.get("severity", "INFO")).upper()
        if sev_str not in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            sev_str = "INFO"

        finding_id = str(uuid.uuid4())
        evidence_status = "INSUFFICIENT_CONTEXT"
        if "Evidence Status: CONFIRMED" in explanation:
            evidence_status = "CONFIRMED"
        elif "Evidence Status: LIKELY" in explanation:
            evidence_status = "LIKELY"

        sf = StructuredFinding(
            finding_id=finding_id,
            project_id=request.project_id or "unknown",
            file=request.file_path or "unknown",
            function=vuln.get("function_name"),
            line_start=vuln.get("line", 0),
            line_end=vuln.get("line", 0),
            severity=SeverityEnum(sev_str),
            category=vuln.get("category", vuln.get("type", "UNKNOWN")),
            title=f"{vuln.get('type', 'Finding')} detected",
            finding=(
                explanation
                if explanation
                else vuln.get("description", vuln.get("message", "Vulnerability found"))
            ),
            evidence=vuln.get("code", ""),
            source=vuln.get("source", "PROJECT_RULE"),
            confidence=confidence,
            rule=vuln.get("rule") or vuln.get("type"),
            diagnostic_message=vuln.get("description") or vuln.get("message"),
            evidence_status=evidence_status,
            explanation_quality=explanation_quality,
        )

        try:
            from app.review.findings import save_finding
            from app.review.audit import log_audit_event
            import json

            save_finding(sf)

            rag_sources_list = (
                [doc.metadata.get("source", "unknown") for doc in context_docs]
                if context_docs
                else []
            )

            log_audit_event(
                event_type="ANALYSIS",
                finding_id=finding_id,
                user="system",
                project_id=request.project_id or "unknown",
                repo_version=getattr(request, "repo_version", "HEAD"),
                file=request.file_path or "unknown",
                line=vuln.get("line", 0),
                detection_source=vuln.get("source", "PROJECT_RULE"),
                model_name=provider,
                rag_sources=json.dumps(rag_sources_list),
                ai_explanation=sf.finding,
                confidence=confidence,
                review_status="PENDING_REVIEW",
            )
        except Exception as e:
            print(f"[WARNING] Could not save finding to DB: {e}")

        results.append(sf)

    response_status = "PARTIAL" if warnings else "SUCCESS"

    return AnalysisResponse(
        vulnerabilities=results,
        total_vulnerabilities=len(results),
        status=response_status,
        warnings=warnings,
    )
