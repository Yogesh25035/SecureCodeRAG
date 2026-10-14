import sys, os
sys.path.insert(0, os.path.abspath('backend'))
from app.main import app
from app.core.auth import get_current_user
from fastapi.testclient import TestClient
app.dependency_overrides[get_current_user] = lambda: {"username": "admin", "role": "ADMIN", "projects": ["*"]}
client = TestClient(app)
code = """
void test_strcpy() {
    char dest[10];
    char src[20] = "abcdefghij";
    strcpy(dest, src);
}
"""
print(client.post("/api/analyze", json={"code": code, "language": "c"}).json())
