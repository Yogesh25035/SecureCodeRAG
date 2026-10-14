from app.vectorstore.index import get_vectorstore
from app.core.config import settings
from app.core.embeddings import get_embeddings
from typing import Optional

class VulnerabilityRetriever:
    """Retrieves relevant documentation (OWASP, Automotive) and codebase context for detected vulnerabilities"""
    
    def __init__(self, project_id: Optional[str] = None):
        self.knowledge_vectorstore = get_vectorstore("knowledge")
        self.project_vectorstore = None
        if project_id:
            try:
                self.project_vectorstore = get_vectorstore(namespace=project_id)
            except Exception as e:
                print(f"Error retrieving repo vectorstore for {project_id}: {e}")
                
        self.top_k = settings.TOP_K
        self.embeddings = get_embeddings()
    
    def retrieve(self, vulnerability_type: str, top_k: int = None, project_id: Optional[str] = None):
        """
        Retrieve relevant documentation for a vulnerability type
        
        Args:
            vulnerability_type: Type of vulnerability (e.g., "SQL Injection")
            top_k: Number of documents to retrieve (default: from settings)
            project_id: Ignored (passed for compatibility, handled in __init__)
            
        Returns:
            List of relevant document chunks
        """
        if top_k is None:
            top_k = self.top_k
            
        enhanced_query = f"secure coding guidance, rationale, and safe practices for {vulnerability_type}"
        
        # 1. Generate query embedding once for reuse
        try:
            query_embedding = self.embeddings.embed_query(enhanced_query)
        except Exception as e:
            print(f"Error generating query embedding: {e}")
            return []
            
        docs = []
        
        # Search global knowledge base
        try:
            import time
            start_t_k = time.time()
            k_docs = self.knowledge_vectorstore.similarity_search_by_vector(
                embedding=query_embedding,
                k=top_k
            )
            elapsed_k = time.time() - start_t_k
            print(f"[TIMING] Knowledge similarity_search took {elapsed_k:.3f}s")
            docs.extend(k_docs)
        except Exception as e:
            print(f"Error retrieving knowledge documents: {e}")
            
        # Search project-specific knowledge base
        if self.project_vectorstore:
            try:
                start_t_r = time.time()
                r_docs = self.project_vectorstore.similarity_search_by_vector(
                    embedding=query_embedding,
                    k=top_k
                )
                elapsed_r = time.time() - start_t_r
                print(f"[TIMING] Repo similarity_search took {elapsed_r:.3f}s")
                
                # Filter out the dummy empty document we use for initialization
                r_docs = [doc for doc in r_docs if doc.page_content != "empty"]
                docs.extend(r_docs)
            except Exception as e:
                print(f"Error retrieving repo documents: {e}")
                
        # Sort or just return the combined top docs
        return docs[:top_k * 2]

