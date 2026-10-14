import subprocess

def get_repo_info(repo_path: str):
    try:
        commit_hash = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=repo_path).decode().strip()
        branch = subprocess.check_output(['git', 'rev-parse', '--abbrev-ref', 'HEAD'], cwd=repo_path).decode().strip()
        return {
            "commit": commit_hash,
            "branch": branch
        }
    except Exception:
        return {
            "commit": "unknown",
            "branch": "unknown"
        }
