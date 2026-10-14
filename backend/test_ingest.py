import json
from app.repository.manager import ingest_repository

repo = ingest_repository('data/demo_repository')
print(json.dumps(repo, indent=2))
