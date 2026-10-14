from app.core.llm import get_llm
from app.rag.prompts import EXPLANATION_PROMPT
import logging

logger = logging.getLogger(__name__)

def build_missing_include_explanation(vulnerability: dict) -> str:
    header = vulnerability.get("description") or vulnerability.get("code") or "The header could not be resolved."
    return (
        "Root Cause:\n"
        f"Cppcheck reported an unresolved include: {header}\n\n"
        "Impact:\n"
        "This is an informational build/configuration diagnostic, not proof of a security vulnerability. "
        "The project may fail to compile or may use an unintended include path.\n\n"
        "Recommendation:\n"
        "Verify that the header exists and that the compiler include paths and build configuration are correct. "
        "Use the same include-path settings for Cppcheck as for the project build.\n\n"
        "Guidance Reference:\n"
        "General build-configuration guidance supports resolving missing headers.\n\n"
        "Evidence Status:\n"
        "INSUFFICIENT_CONTEXT"
    )


class ExplanationGenerator:
    """
    Generates concise AI explanations for already-detected
    vulnerabilities using RAG context.

    The deterministic analyzer remains authoritative.
    """

    def __init__(self):
        self.llm = get_llm()
        self.prompt = EXPLANATION_PROMPT

    def generate_explanation(
        self,
        vulnerability: dict,
        context_docs: list
    ) -> str:
        rule = str(vulnerability.get("rule") or vulnerability.get("type") or "").lower()
        if rule in {"missinginclude", "missingincludesystem"}:
            return build_missing_include_explanation(vulnerability)

        # ---------------------------------------------------------
        # 1. Prepare RAG context
        # ---------------------------------------------------------
        context_parts = []

        for doc in context_docs[:2]:
            if hasattr(doc, "page_content"):
                content = doc.page_content.strip()
                
                # Append metadata for citations
                if hasattr(doc, "metadata"):
                    meta = doc.metadata
                    source = meta.get("source", "Unknown")
                    ref = meta.get("reference", "None")
                    content += f"\n[Source: {source} | Reference: {ref}]"

                if content:
                    context_parts.append(content)

        context = "\n\n".join(context_parts)

        if not context:
            context = "No specific guidance was retrieved."

        # ---------------------------------------------------------
        # 2. Deterministic finding information
        # ---------------------------------------------------------
        vulnerability_type = (
            vulnerability.get("category")
            or vulnerability.get("type")
            or "UNKNOWN"
        )

        severity = vulnerability.get(
            "severity",
            "UNKNOWN"
        )

        file_path = vulnerability.get(
            "file",
            "unknown"
        )

        line_num = vulnerability.get(
            "line",
            "unknown"
        )

        code_snippet = vulnerability.get(
            "code",
            ""
        )

        # ---------------------------------------------------------
        # 3. Build controlled prompt
        # ---------------------------------------------------------
        prompt = self.prompt.format(
            vulnerability_type=vulnerability_type,
            severity=severity,
            file_path=file_path,
            line_num=line_num,
            code_snippet=code_snippet,
            context=context
        )

        # ---------------------------------------------------------
        # 4. Generate explanation and Validate (Phase 12)
        # ---------------------------------------------------------
        try:
            import time
            start_t_llm = time.time()
            print(f"[TIMING] LLM generation started...")
            response = self.llm.invoke(prompt)
            elapsed_llm = time.time() - start_t_llm
            print(f"[TIMING] LLM generation finished in {elapsed_llm:.3f}s")

            if hasattr(response, "content"):
                result = response.content.strip()
            else:
                result = str(response).strip()
                
            if not result:
                raise ValueError("Empty response from LLM")
                
            if len(result) > 2000:
                raise ValueError("Response from LLM excessively long")
                
            result_lower = result.lower()
            
            # Contradiction Detection
            if vulnerability_type in ["BOUNDARY_VIOLATION", "UNSAFE_STRING_OPS"]:
                if "null-pointer dereference" in result_lower or "dereferencing a null pointer" in result_lower:
                    raise ValueError(f"LLM contradicted finding by claiming null pointer dereference for {vulnerability_type}")

            return result

        except Exception as e:
            logger.error(f"[ExplanationGenerator] AI explanation failed at validation/inference stage. Exception type: {type(e).__name__}, Message: {str(e)}")
            fallback = (
                f"Root Cause:\nThe deterministic analyzer identified {vulnerability_type} at line {line_num}. "
                f"The provided code snippet uses operations that may be unsafe without sufficient bounds or null checks.\n\n"
                f"Impact:\nExploitability cannot be definitively confirmed from this snippet alone.\n\n"
                f"Recommendation:\nReview the code context to ensure proper validations.\n\n"
                f"Guidance Reference:\nGeneral secure-coding guidance supports avoiding this unsafe operation.\n\n"
                f"Evidence Status:\nINSUFFICIENT_CONTEXT"
            )
            return fallback