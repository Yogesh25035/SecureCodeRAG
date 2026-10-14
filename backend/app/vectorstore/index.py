from pathlib import Path

from langchain_core.documents import Document
from langchain_community.vectorstores import FAISS
import re

from app.core.embeddings import get_embeddings
from app.core.config import settings


# -------------------------------------------------------------------
# Paths
# -------------------------------------------------------------------

APP_DIR = Path(__file__).resolve().parents[1]

DATA_DIR = APP_DIR / "data"

VECTORSTORE_DIR = (
    Path(__file__).resolve().parents[2]
    / settings.VECTORSTORE_PATH
)


# -------------------------------------------------------------------
# Load local knowledge documents
# -------------------------------------------------------------------

def _parse_knowledge_metadata(text: str) -> dict:
    """
    Extract structured metadata fields from knowledge documents.
    Fields parsed: TOPIC, CATEGORY, APPLICABLE_VULNERABILITIES, REFERENCE, SOURCE
    """
    meta = {}
    field_pattern = re.compile(
        r'^(?P<key>TOPIC|CATEGORY|APPLICABLE_VULNERABILITIES|REFERENCE|SOURCE):\s*(?P<value>.+)',
        re.MULTILINE
    )
    for match in field_pattern.finditer(text):
        key = match.group('key').lower().replace('applicable_vulnerabilities', 'applicable')
        meta[key] = match.group('value').strip()
    return meta


def load_knowledge_documents():
    """
    Load local automotive/security knowledge files.
    Parses structured metadata (TOPIC, CATEGORY, APPLICABLE_VULNERABILITIES, REFERENCE, SOURCE).
    """

    documents = []

    knowledge_dirs = [
        DATA_DIR / "automotive_guidelines",
        DATA_DIR / "secure_coding",
        DATA_DIR / "historical_findings",
    ]

    for directory in knowledge_dirs:

        if not directory.exists():
            continue

        for file_path in directory.rglob("*"):

            if not file_path.is_file():
                continue

            if file_path.suffix.lower() not in {
                ".txt",
                ".md",
                ".csv",
                ".json",
            }:
                continue

            try:
                text = file_path.read_text(
                    encoding="utf-8",
                    errors="ignore"
                ).strip()

                if not text:
                    continue

                # Parse embedded metadata
                parsed_meta = _parse_knowledge_metadata(text)

                metadata = {
                    "source": parsed_meta.get("source", str(file_path.relative_to(DATA_DIR))),
                    "category": parsed_meta.get("category", directory.name),
                    "topic": parsed_meta.get("topic", file_path.stem),
                    "applicable": parsed_meta.get("applicable", ""),
                    "reference": parsed_meta.get("reference", ""),
                    "file_name": file_path.name,
                    "knowledge_type": directory.name,
                }

                documents.append(
                    Document(
                        page_content=text,
                        metadata=metadata,
                    )
                )

            except Exception as e:
                print(
                    f"[WARNING] Could not read "
                    f"{file_path}: {e}"
                )

    print(
        f"[INFO] Loaded {len(documents)} knowledge documents"
    )

    return documents



# -------------------------------------------------------------------
# Create FAISS vector store
# -------------------------------------------------------------------

def create_vectorstore(namespace: str = "knowledge"):

    if namespace == "knowledge":
        documents = load_knowledge_documents()
        if not documents:
            raise RuntimeError(
                "No knowledge documents found. "
                "Add documents under backend/app/data/"
            )
    else:
        # For non-knowledge namespaces, start empty or raise if not being populated
        # FAISS needs at least one document to initialize, so we will handle this outside.
        # Actually, FAISS.from_texts(["dummy"], embeddings) is a hack to create an empty index.
        # Wait, if we are creating a project vectorstore, we usually add documents directly in add_repository_to_vectorstore.
        # So we can just return None here, and let the caller create it.
        pass

    print(
        f"[INFO] Creating FAISS vector store for namespace: {namespace}..."
    )

    embeddings = get_embeddings()

    if namespace == "knowledge":
        vectorstore = FAISS.from_documents(
            documents,
            embeddings
        )
    else:
        # Create an empty vectorstore with a dummy document to initialize dimensions
        from langchain_core.documents import Document
        vectorstore = FAISS.from_documents([Document(page_content="empty", metadata={"project_id": namespace})], embeddings)

    ns_dir = VECTORSTORE_DIR / namespace
    ns_dir.mkdir(parents=True, exist_ok=True)
    
    vectorstore.save_local(str(ns_dir))
    return vectorstore


# -------------------------------------------------------------------
# Get existing or create new vector store
# -------------------------------------------------------------------

def get_vectorstore(namespace: str = "knowledge"):

    ns_dir = VECTORSTORE_DIR / namespace
    index_file = ns_dir / "index.faiss"
    metadata_file = ns_dir / "index.pkl"

    import time
    start_t_emb = time.time()
    embeddings = get_embeddings()
    elapsed_emb = time.time() - start_t_emb
    print(f"[TIMING] get_embeddings() for namespace {namespace} took {elapsed_emb:.3f}s")

    # Existing FAISS index
    if index_file.exists() and metadata_file.exists():
        try:
            start_t_faiss = time.time()
            print(f"[TIMING] FAISS.load_local() for namespace {namespace} started...")
            vs = FAISS.load_local(
                str(ns_dir),
                embeddings,
                allow_dangerous_deserialization=True
            )
            elapsed_faiss = time.time() - start_t_faiss
            print(f"[TIMING] FAISS.load_local() finished in {elapsed_faiss:.3f}s")
            return vs
        except Exception as e:
            print(f"[WARNING] Existing vector store could not be loaded: {e}")

    # No existing index → create it
    start_t_create = time.time()
    print(f"[TIMING] create_vectorstore() for namespace {namespace} started...")
    vs = create_vectorstore(namespace=namespace)
    elapsed_create = time.time() - start_t_create
    print(f"[TIMING] create_vectorstore() finished in {elapsed_create:.3f}s")
    return vs

# -------------------------------------------------------------------
# Add repository code to vector store
# -------------------------------------------------------------------

def add_repository_to_vectorstore(repo_data: dict):
    from langchain_core.documents import Document
    import json
    
    print(f"[INFO] Adding repository {repo_data.get('project_name')} to vector store...")
    documents = []
    project_id = repo_data.get("project_id", "unknown")
    project_name = repo_data.get("project_name", "unknown")
    git_version = repo_data.get("git_info", {}).get("commit", "unknown")
    
    for f in repo_data.get("files", []):
        # File-level metadata
        file_metadata = {
            "source": f["path"],
            "project_id": project_id,
            "project_name": project_name,
            "file_type": f["type"],
            "hash": f.get("hash", ""),
            "version": git_version,
            "includes": json.dumps(f.get("includes", [])),
            "dependencies": json.dumps(f.get("dependencies", [])),
        }
        
        # 1. Add whole file context (useful for headers/globals)
        documents.append(
            Document(
                page_content=f["content"],
                metadata=file_metadata
            )
        )
        
        # 2. Add individual functions as chunks
        for func in f.get("functions", []):
            start = func["start_line"]
            end = func["end_line"]
            # Extract function body snippet
            lines = f["content"].split("\n")
            # Bounds check
            start_idx = max(0, start - 1)
            end_idx = min(len(lines), end)
            func_content = "\n".join(lines[start_idx:end_idx])
            
            func_metadata = file_metadata.copy()
            func_metadata.update({
                "function_name": func["name"],
                "return_type": func["return_type"],
                "parameters": json.dumps(func["parameters"]),
                "calls": json.dumps(func["calls"]),
                "start_line": start,
                "end_line": end
            })
            
            documents.append(
                Document(
                    page_content=func_content,
                    metadata=func_metadata
                )
            )
            
    if not documents:
        print("[WARNING] No valid code files found to add to vector store.")
        return
        
    vs = get_vectorstore(namespace=project_id)
    
    # We started with an empty document for initialization in get_vectorstore, 
    # we can just add these documents to it. 
    # Technically, FAISS doesn't mind the empty doc.
    vs.add_documents(documents)
    
    ns_dir = VECTORSTORE_DIR / project_id
    vs.save_local(str(ns_dir))
    print(f"[INFO] Successfully added {len(documents)} structural chunks to vector store namespace {project_id}.")