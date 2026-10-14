"""
TEMPORARY PROFILING SCRIPT
===========================
Purpose : Measure SecureCodeRAG /api/analyze performance.
Scope   : READ-ONLY instrumentation - no existing files are modified.
Remove  : Delete this file when profiling is complete.
"""
import sys
import io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

import os
import sys
import time
import asyncio
from dotenv import load_dotenv

load_dotenv(os.path.join(os.path.dirname(__file__), "backend", ".env"))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "backend")))

# ─── Patch helpers (temporary, in-memory only) ────────────────────────────────

timings = {
    "static_scan_ms": 0.0,
    "retriever_init_ms": 0.0,
    "vectorstore_init_ms": 0.0,
    "llm_init_ms": 0.0,
    "rag_calls": 0,
    "rag_total_ms": 0.0,
    "llm_calls": 0,
    "llm_total_ms": 0.0,
    "llm_times_ms": [],
    "rag_times_ms": [],
    "per_vuln_ms": [],
}

# ─── Import components ─────────────────────────────────────────────────────────

from app.security.static_scan import StaticScanner
from app.core.config import settings

# ─── Test code (4 vulnerabilities) ────────────────────────────────────────────

TEST_CODE = """
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void copy_data(char *input) {
    char buffer[10];
    strcpy(buffer, input);       /* UNSAFE_STRING_OPS + BOUNDARY_VIOLATION */
}

void test_pointer() {
    char *ptr = NULL;
    printf("%d\\n", *ptr);       /* NULL_POINTER */
}

void resource_leak() {
    char *mem = (char *)malloc(64);
    /* missing free() */
    return;                      /* RESOURCE_LEAK */
}

int main() {
    char input[100];
    copy_data(input);
    test_pointer();
    resource_leak();
    return 0;
}
"""


async def run_profile(run_index: int):
    print(f"\n{'='*60}")
    print(f"  RUN #{run_index}")
    print(f"{'='*60}")

    run_timings = {k: 0.0 for k in timings}
    run_timings["rag_calls"] = 0
    run_timings["llm_calls"] = 0
    run_timings["llm_times_ms"] = []
    run_timings["rag_times_ms"] = []
    run_timings["per_vuln_ms"] = []

    # ── 1. Static Scan ─────────────────────────────────────────────────────────
    scanner = StaticScanner()
    t0 = time.perf_counter()
    vulnerabilities = scanner.scan(TEST_CODE)
    run_timings["static_scan_ms"] = (time.perf_counter() - t0) * 1000

    print(f"\n[STATIC SCAN]  {len(vulnerabilities)} findings in {run_timings['static_scan_ms']:.2f} ms")
    for v in vulnerabilities:
        print(f"  line {v['line']:>3}  {v['type']:<25}  {v['severity']}")

    provider = settings.LLM_PROVIDER.lower()
    if provider == "dummy":
        print("\n[PROFILE] LLM_PROVIDER=dummy – RAG and LLM steps will be skipped.")
        _print_report(run_timings)
        return

    # ── 2. Retriever / VectorStore Init ────────────────────────────────────────
    from app.rag.retriever import VulnerabilityRetriever

    t0 = time.perf_counter()
    # VectorStore is loaded inside VulnerabilityRetriever.__init__
    # We time the whole retriever init to get VS + retriever together,
    # then isolate VS separately via a direct call below.
    retriever = VulnerabilityRetriever()
    run_timings["retriever_init_ms"] = (time.perf_counter() - t0) * 1000

    # VectorStore alone (second call uses cached instance from module-level)
    from app.vectorstore.index import get_vectorstore
    t0 = time.perf_counter()
    _vs = get_vectorstore()          # hits module cache – measures pure Python overhead
    run_timings["vectorstore_init_ms"] = (time.perf_counter() - t0) * 1000

    # ── 3. LLM Init ────────────────────────────────────────────────────────────
    from app.rag.generator import ExplanationGenerator
    from app.core.llm import get_llm

    t0 = time.perf_counter()
    _llm = get_llm()
    run_timings["llm_init_ms"] = (time.perf_counter() - t0) * 1000

    t0 = time.perf_counter()
    generator = ExplanationGenerator()
    gen_init_ms = (time.perf_counter() - t0) * 1000

    print(f"\n[INIT]")
    print(f"  retriever (includes VS first load) : {run_timings['retriever_init_ms']:.2f} ms")
    print(f"  vectorstore (cached / 2nd call)    : {run_timings['vectorstore_init_ms']:.2f} ms")
    print(f"  llm (get_llm)                      : {run_timings['llm_init_ms']:.2f} ms")
    print(f"  generator (__init__)               : {gen_init_ms:.2f} ms")

    # ── 4. Per-vulnerability loop ───────────────────────────────────────────────
    from app.security.code_context import get_code_context
    from app.security.confidence import calculate_confidence

    print(f"\n[PER-VULNERABILITY]")
    for i, vuln in enumerate(vulnerabilities):
        t_vuln_start = time.perf_counter()

        # RAG retrieval
        category = vuln.get("category") or vuln.get("type") or "UNKNOWN"
        rag_query = f"{category} {vuln.get('code', '')} {vuln.get('description', '')}"

        t_rag = time.perf_counter()
        context_docs = retriever.retrieve(rag_query, top_k=2)
        rag_elapsed = (time.perf_counter() - t_rag) * 1000
        run_timings["rag_calls"] += 1
        run_timings["rag_times_ms"].append(rag_elapsed)

        # Code context
        context_snippet = get_code_context(TEST_CODE, vuln.get("line"))
        vuln_with_context = vuln.copy()
        if context_snippet:
            vuln_with_context["code"] = context_snippet

        # LLM
        t_llm = time.perf_counter()
        explanation = generator.generate_explanation(vuln_with_context, context_docs)
        llm_elapsed = (time.perf_counter() - t_llm) * 1000
        run_timings["llm_calls"] += 1
        run_timings["llm_times_ms"].append(llm_elapsed)

        confidence = calculate_confidence(vuln, context_docs)

        vuln_total_ms = (time.perf_counter() - t_vuln_start) * 1000
        run_timings["per_vuln_ms"].append(vuln_total_ms)

        print(f"  [{i+1}] {vuln['type']:<25}  RAG={rag_elapsed:>7.1f}ms  LLM={llm_elapsed:>8.1f}ms  total={vuln_total_ms:>8.1f}ms  conf={confidence}")

    run_timings["rag_total_ms"] = sum(run_timings["rag_times_ms"])
    run_timings["llm_total_ms"] = sum(run_timings["llm_times_ms"])

    _print_report(run_timings)
    return run_timings


def _print_report(t: dict):
    llm_times = t.get("llm_times_ms", [])
    rag_times = t.get("rag_times_ms", [])
    per_vuln  = t.get("per_vuln_ms", [])

    llm_avg = (sum(llm_times) / len(llm_times)) if llm_times else 0.0
    rag_avg = (sum(rag_times) / len(rag_times)) if rag_times else 0.0

    total_ms = (
        t["static_scan_ms"]
        + t["retriever_init_ms"]
        + t["llm_init_ms"]
        + t["rag_total_ms"]
        + t["llm_total_ms"]
    )

    print(f"""
┌─────────────────────────────────────────────────────────┐
│                  PERFORMANCE REPORT                     │
├─────────────────────────────────────────────────────────┤
│ STATIC SCAN                                             │
│   time = {t['static_scan_ms']:>8.2f} ms                              │
├─────────────────────────────────────────────────────────┤
│ RAG                                                     │
│   calls                = {t['rag_calls']:>4}                          │
│   total time           = {t['rag_total_ms']:>8.2f} ms                │
│   average per call     = {rag_avg:>8.2f} ms                │
│   individual calls (ms): {[round(x,1) for x in rag_times]}
├─────────────────────────────────────────────────────────┤
│ OLLAMA                                                  │
│   calls                = {t['llm_calls']:>4}                          │
│   total generation     = {t['llm_total_ms']:>8.2f} ms                │
│   average per call     = {llm_avg:>8.2f} ms                │
│   individual calls (ms): {[round(x,1) for x in llm_times]}
├─────────────────────────────────────────────────────────┤
│ INITIALIZATION                                          │
│   retriever + VS first load = {t['retriever_init_ms']:>8.2f} ms      │
│   VS second call (cached)   = {t['vectorstore_init_ms']:>8.2f} ms      │
│   LLM (get_llm())           = {t['llm_init_ms']:>8.2f} ms      │
├─────────────────────────────────────────────────────────┤
│ PER-VULNERABILITY totals (ms): {[round(x,1) for x in per_vuln]}
├─────────────────────────────────────────────────────────┤
│ TOTAL                                                   │
│   request time = {total_ms:>8.2f} ms                          │
├─────────────────────────────────────────────────────────┤
│ BOTTLENECK ANALYSIS                                     │
│   scan   : {t['static_scan_ms']/max(total_ms,1)*100:>5.1f}%                                    │
│   RAG    : {t['rag_total_ms']/max(total_ms,1)*100:>5.1f}%                                    │
│   LLM    : {t['llm_total_ms']/max(total_ms,1)*100:>5.1f}%                                    │
│   init   : {(t['retriever_init_ms']+t['llm_init_ms'])/max(total_ms,1)*100:>5.1f}%                                    │
└─────────────────────────────────────────────────────────┘""")


async def main():
    print("SecureCodeRAG – Performance Profiling")
    print(f"LLM_PROVIDER = {settings.LLM_PROVIDER}")
    print(f"LLM_MODEL    = {settings.LLM_MODEL}")

    results = []
    for run in range(1, 2):   # single run (run #1 data already captured)
        r = await run_profile(run)
        if r:
            results.append(r)

    if len(results) >= 2:
        print("\n" + "="*60)
        print("  COLD vs WARM COMPARISON")
        print("="*60)
        labels = ["static_scan_ms", "retriever_init_ms", "llm_init_ms", "rag_total_ms", "llm_total_ms"]
        for label in labels:
            cold = results[0].get(label, 0)
            warm = results[1].get(label, 0)
            print(f"  {label:<30} cold={cold:>8.1f}ms   warm={warm:>8.1f}ms")


if __name__ == "__main__":
    asyncio.run(main())
