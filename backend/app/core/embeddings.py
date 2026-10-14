import hashlib
import os
import requests
from langchain.embeddings.base import Embeddings
from app.core.config import settings


from functools import lru_cache


class DeterministicEmbeddings(Embeddings):
    """Pure-Python embedding fallback for local/offline environments.

    This avoids the hard dependency on Ollama during ingestion when the user is
    running the app without a local model server. It keeps embeddings stable and
    deterministic by hashing text content into a fixed-length vector.
    """

    def __init__(self, dimension: int = 128):
        self.dimension = dimension

    def _vector_for_text(self, text: str):
        values = []
        for i in range(self.dimension):
            chunk = hashlib.sha256(f"{text}\x1f{i}".encode("utf-8", errors="ignore")).digest()
            value = int.from_bytes(chunk, byteorder="big", signed=False) / float(1 << 256)
            values.append((value * 2.0) - 1.0)
        return values

    def embed_documents(self, texts):
        return [self._vector_for_text(text) for text in texts]

    def embed_query(self, text):
        return self._vector_for_text(text)

@lru_cache(maxsize=1000)
def _cached_embed_query(model: str, base_url: str, text: str):
    import time
    start_t = time.time()
    print(f"[TIMING] Embedding query API call started...")
    
    response = requests.post(
        f"{base_url}/api/embed",
        json={
            "model": model,
            "input": [text]
        },
        timeout=120
    )

    response.raise_for_status()

    data = response.json()
    elapsed = time.time() - start_t
    print(f"[TIMING] Embedding query API call finished in {elapsed:.3f}s")
    
    # Return as tuple to prevent callers from modifying the cached object
    return tuple(data["embeddings"][0])


class OllamaEmbeddings(Embeddings):
    """
    Lightweight Ollama-based embeddings.
    Avoids sentence-transformers and PyTorch.
    """

    def __init__(
        self,
        model="nomic-embed-text",
        base_url=None
    ):
        self.model = model
        self.base_url = (
            base_url
            or settings.OLLAMA_BASE_URL
        ).rstrip("/")

    def embed_documents(self, texts):
        if not texts:
            return []
            
        import time
        start_t = time.time()
        print(f"[TIMING] Embedding API call for {len(texts)} documents started...")

        response = requests.post(
            f"{self.base_url}/api/embed",
            json={
                "model": self.model,
                "input": texts
            },
            timeout=120
        )

        response.raise_for_status()

        data = response.json()
        elapsed = time.time() - start_t
        print(f"[TIMING] Embedding API call finished in {elapsed:.3f}s")
        return data["embeddings"]

    def embed_query(self, text):
        # Convert tuple back to list to ensure caller gets a mutable copy
        return list(_cached_embed_query(self.model, self.base_url, text))


def get_embeddings():
    """
    Prefer Ollama when available, but fall back to a deterministic embedding
    implementation so the app continues to work in local/offline development.
    """

    model = os.getenv(
        "OLLAMA_EMBED_MODEL",
        "nomic-embed-text"
    )

    base_url = settings.OLLAMA_BASE_URL

    try:
        response = requests.get(f"{base_url}/api/tags", timeout=5)
        if response.status_code == 200:
            print(
                f"[INFO] Using Ollama Embeddings "
                f"(Model: {model} at {base_url})"
            )
            return OllamaEmbeddings(
                model=model,
                base_url=base_url
            )
    except Exception:
        pass

    print(
        f"[WARNING] Ollama is unavailable at {base_url}; "
        "falling back to deterministic in-process embeddings."
    )
    return DeterministicEmbeddings()