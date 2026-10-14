import sys, os
sys.path.insert(0, os.path.abspath('backend'))

from app.security.compiler_logs import parse_compiler_logs, associate_warnings_with_repo

# ---------------------------------------------------------------------------
# Test 1: Multi-format parsing
# ---------------------------------------------------------------------------
def test_parse_formats():
    log = """\
main.c:12:3: warning: unused variable 'x' [-Wunused-variable]
utils.c:45:8: error: implicit declaration of function 'foo' [-Wimplicit-function-declaration]
src/alloc.c(77): warning C4701: potentially uninitialized local variable 'ptr' used
"isr.c",23  Warning[Pa082]: undefined behavior is detected
[buffer.c:10]: (error) Buffer is accessed out of bounds [bufferAccessOutOfBounds]
"""
    results = parse_compiler_logs(log)
    print(f"Parsed {len(results)} warnings:")
    for r in results:
        print(f"  [{r['source']}] {r['file']}:{r['line']} ({r['severity']}) {r['message'][:60]}")

    assert len(results) == 5, f"Expected 5, got {len(results)}"

    files = [r["file"] for r in results]
    assert "main.c" in files
    assert "utils.c" in files
    assert "src/alloc.c" in files
    assert "isr.c" in files
    assert "buffer.c" in files

    sources = set(r["source"] for r in results)
    assert sources == {"COMPILER"}, f"Expected all COMPILER, got {sources}"

    # Check warning codes extracted
    gcc_warn = next(r for r in results if r["file"] == "main.c")
    assert "-Wunused-variable" in gcc_warn.get("code", ""), f"Expected -Wunused-variable in code, got: {gcc_warn}"

    msvc_warn = next(r for r in results if r["file"] == "src/alloc.c")
    assert "C4701" in msvc_warn.get("code", "")

    print("PASS: Multi-format parsing")


# ---------------------------------------------------------------------------
# Test 2: Deduplication
# ---------------------------------------------------------------------------
def test_dedup():
    log = """\
main.c:12:3: warning: unused variable 'x' [-Wunused-variable]
main.c:12:3: warning: unused variable 'x' [-Wunused-variable]
"""
    results = parse_compiler_logs(log)
    assert len(results) == 1, f"Expected 1 after dedup, got {len(results)}"
    print("PASS: Deduplication")


# ---------------------------------------------------------------------------
# Test 3: Repo association
# ---------------------------------------------------------------------------
def test_repo_association():
    warnings = [
        {"file": "main.c", "line": 7, "severity": "MEDIUM",
         "message": "implicit declaration", "code": "W1234",
         "source": "COMPILER", "category": "COMPILER_WARNING", "type": "COMPILER_WARNING"},
    ]
    repo_data = {
        "files": [
            {
                "path": "main.c",
                "content": "int main() {\n    // line 2\n    // line 3\n    // line 4\n    // line 5\n    // line 6\n    implicitly_declared();\n}",
                "type": "c_cpp"
            }
        ]
    }
    enriched = associate_warnings_with_repo(warnings, repo_data)
    assert enriched[0]["repo_found"] is True, "Expected repo_found=True"
    assert enriched[0]["file_path"] == "main.c"
    assert "implicitly_declared" in enriched[0]["code"], f"Code extraction failed: {enriched[0]['code']}"
    print("PASS: Repo association — source file located and evidence extracted")


# ---------------------------------------------------------------------------
# Test 4: FastAPI endpoint smoke test
# ---------------------------------------------------------------------------
def test_endpoint():
    from fastapi.testclient import TestClient
    from app.main import app

    from app.core.auth import get_current_user
    
    def override_get_current_user():
        return {"username": "admin", "role": "ADMIN", "projects": ["*"]}
        
    app.dependency_overrides[get_current_user] = override_get_current_user
    client = TestClient(app)

    log_content = b"utils.c:45:8: error: implicit declaration of function 'copy_data' [-Wimplicit-function-declaration]\n"

    response = client.post(
        "/api/build-log/upload",
        files={"file": ("build.log", log_content, "text/plain")},
        data={}
    )
    assert response.status_code == 200, f"Endpoint failed: {response.text}"
    data = response.json()
    assert data["warnings_found"] == 1
    assert data["findings"][0]["type"] == "COMPILER_WARNING"
    assert data["findings"][0]["source"] == "COMPILER"
    assert data["findings"][0]["file"] == "utils.c"
    assert data["findings"][0]["line"] == 45
    print(f"PASS: Endpoint smoke test — {data['warnings_found']} warning(s) returned")
    print(f"      Explanation: {data['findings'][0]['explanation'][:80]}...")


# ---------------------------------------------------------------------------
# Test 5: No crash on garbage input
# ---------------------------------------------------------------------------
def test_graceful_garbage():
    results = parse_compiler_logs("this is not a compiler log\n" * 100)
    assert results == []
    print("PASS: Graceful handling of garbage input")


if __name__ == "__main__":
    test_parse_formats()
    test_dedup()
    test_repo_association()
    test_endpoint()
    test_graceful_garbage()
    print("\nAll Phase 5 acceptance tests PASSED.")
