import os
import re

replacements = [
    (
        r"backend/app/schemas/request.py",
        [
            ("repo_id: Optional[str]", "project_id: Optional[str]"),
            ('"repo_id": "optional-uuid-here"', '"project_id": "optional-uuid-here"')
        ]
    ),
    (
        r"backend/app/schemas/findings.py",
        [
            ("repository: str", "project_id: str")
        ]
    ),
    (
        r"frontend/src/types/analysis.ts",
        [
            ("repository: string;", "project_id: string;")
        ]
    ),
    (
        r"backend/app/vectorstore/index.py",
        [
            ("repo_id=", "project_id="),
            ("repo_id:", "project_id:"),
            ("repo_id = repo_data", "project_id = repo_data"),
            ("repo_id", "project_id")
        ]
    ),
    (
        r"backend/app/rag/retriever.py",
        [
            ("repo_id: Optional[str]", "project_id: Optional[str]"),
            ("if repo_id:", "if project_id:"),
            ("namespace=repo_id", "namespace=project_id"),
            ("for repo_id:", "for project_id:")
        ]
    ),
    (
        r"backend/app/repository/manager.py",
        [
            ("repo_id: str = \"unknown\"", "project_id: str = \"unknown\""),
            ("\"repo_id\": repo_id", "\"project_id\": project_id")
        ]
    ),
    (
        r"backend/app/api/analyze.py",
        [
            ("request.repo_id", "request.project_id"),
            ("repo_id=getattr(request, \"repo_id\", None)", "project_id=getattr(request, \"project_id\", None)"),
            ("repository=request.repo_id", "project_id=request.project_id"),
            ("repository=request.project_id", "project_id=request.project_id")
        ]
    ),
    (
        r"backend/app/api/build_logs.py",
        [
            ("repo_id: Optional[str] = Form(default=None)", "project_id: Optional[str] = Form(default=None)"),
            ("if repo_id:", "if project_id:"),
            ("verify_project_access(current_user, repo_id)", "verify_project_access(current_user, project_id)"),
            ("repo_id=repo_id", "project_id=project_id"),
            ("_get_repo_path_by_id(repo_id)", "_get_repo_path_by_id(project_id)"),
            ("\"repo_id\": repo_id", "\"project_id\": project_id"),
            ("def _get_repo_path_by_id(repo_id: str):", "def _get_repo_path_by_id(project_id: str):"),
            ("repos\", repo_id", "repos\", project_id")
        ]
    ),
    (
        r"backend/app/api/repositories.py",
        [
            ("repo_id =", "project_id ="),
            ("repos\", repo_id", "repos\", project_id"),
            ("repo_id=repo_id", "project_id=project_id"),
            ("\"repo_id\": repo_id", "\"project_id\": project_id")
        ]
    ),
    (
        r"backend/app/review/audit.py",
        [
            ("repository TEXT,", "project_id TEXT,"),
            ("repository: str = \"\",", "project_id: str = \"\","),
            ("repository,", "project_id,"),
            ("repository TEXT", "project_id TEXT")
        ]
    ),
    (
        r"backend/app/review/findings.py",
        [
            ("repository TEXT", "project_id TEXT"),
            ("repository,", "project_id,"),
            ("finding.repository", "finding.project_id"),
            ("def get_findings_by_repository(repository: str)", "def get_findings_by_project_id(project_id: str)"),
            ("WHERE repository = ?', (repository", "WHERE project_id = ?', (project_id"),
            ("old_finding.get(\"repository\"", "old_finding.get(\"project_id\"")
        ]
    ),
    (
        r"backend/tests/test_project_isolation.py",
        [
            ("\"repo_id\"", "\"project_id\""),
            ("repo_id=", "project_id=")
        ]
    )
]

base_dir = r"d:\Techpulse\SecureCodeRAG"

for rel_path, reps in replacements:
    full_path = os.path.join(base_dir, rel_path.replace("/", os.sep))
    if not os.path.exists(full_path):
        print(f"File not found: {full_path}")
        continue
        
    with open(full_path, "r", encoding="utf-8") as f:
        content = f.read()
        
    original = content
    for old, new in reps:
        content = content.replace(old, new)
        
    if content != original:
        with open(full_path, "w", encoding="utf-8") as f:
            f.write(content)
        print(f"Updated {full_path}")
    else:
        print(f"No changes made in {full_path}")
