"""
RAG Embedder — ChromaDB + Ollama nomic-embed-text.

Uses OllamaEmbeddingFunction (Fix #20 — NOT sentence-transformers).
All embeddings are local and FREE.

Usage:
    rag = RAGStore(config)
    context = rag.get_context_for_service("apache", "2.4.49")
"""

import logging
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


class RAGStore:
    """
    Local vector database for pentest knowledge.

    Backed by ChromaDB with Ollama nomic-embed-text embeddings.
    All operations are local and free.
    """

    def __init__(self, config: dict):
        self.config = config
        self.chroma_path = config.get("rag", {}).get("chroma_path", "./data/chroma")
        self.embedding_model = config.get("rag", {}).get("embedding_model", "nomic-embed-text")
        self.ollama_host = config.get("llm", {}).get("ollama_host", "http://localhost:11434")
        self.top_k = config.get("rag", {}).get("top_k", 3)

        self._client = None
        self._collection = None

    def _init_chroma(self):
        """Lazy-initialize ChromaDB with Ollama embeddings."""
        if self._client is not None:
            return

        try:
            import chromadb
            from chromadb.utils.embedding_functions import OllamaEmbeddingFunction

            # Ensure directory exists
            Path(self.chroma_path).mkdir(parents=True, exist_ok=True)

            # Create persistent client
            self._client = chromadb.PersistentClient(path=self.chroma_path)

            # Create embedding function using Ollama (FREE)
            ollama_ef = OllamaEmbeddingFunction(
                url=self.ollama_host,
                model_name=self.embedding_model,
            )

            # Get or create the knowledge collection
            self._collection = self._client.get_or_create_collection(
                name="pentest_knowledge",
                embedding_function=ollama_ef,
                metadata={"description": "Pentesting techniques and exploits"},
            )

            logger.info(
                "RAGStore initialized: %d documents in collection",
                self._collection.count(),
            )
        except ImportError:
            logger.warning("chromadb not installed — RAG disabled")
            raise
        except Exception as e:
            logger.error("Failed to initialize RAGStore: %s", e)
            raise

    @property
    def collection(self):
        """Lazy access to the ChromaDB collection."""
        if self._collection is None:
            self._init_chroma()
        return self._collection

    # ── Query ────────────────────────────────────────────────

    def get_context_for_service(
        self, service: str, version: str = ""
    ) -> str:
        """
        Query knowledge base for exploitation context.

        Args:
            service: Service name (e.g., "apache", "openssh").
            version: Version string (e.g., "2.4.49").

        Returns:
            Concatenated relevant context string.
            Empty string if RAG is not available.
        """
        try:
            query = f"{service} {version} exploitation techniques vulnerabilities".strip()
            results = self.collection.query(
                query_texts=[query],
                n_results=self.top_k,
            )

            if results and results["documents"] and results["documents"][0]:
                context = "\n\n---\n\n".join(results["documents"][0])
                logger.info(
                    "RAG returned %d results for '%s'",
                    len(results["documents"][0]), query,
                )
                return context

        except Exception as e:
            logger.warning("RAG query failed: %s", e)

        return ""

    def get_context_for_cve(self, cve_id: str) -> str:
        """Query knowledge base for a specific CVE."""
        try:
            results = self.collection.query(
                query_texts=[f"{cve_id} exploit proof of concept"],
                n_results=self.top_k,
            )
            if results and results["documents"] and results["documents"][0]:
                return "\n\n---\n\n".join(results["documents"][0])
        except Exception as e:
            logger.warning("RAG CVE query failed: %s", e)
        return ""

    # ── Ingestion ────────────────────────────────────────────

    def add_documents(
        self,
        documents: list[str],
        metadatas: Optional[list[dict]] = None,
        ids: Optional[list[str]] = None,
    ) -> int:
        """
        Add documents to the knowledge base.

        Args:
            documents: List of text chunks.
            metadatas: Optional metadata dicts per document.
            ids: Optional IDs. Auto-generated if not provided.

        Returns:
            Number of documents added.
        """
        import uuid

        if not documents:
            return 0

        if ids is None:
            ids = [f"doc_{uuid.uuid4().hex[:8]}" for _ in documents]

        if metadatas is None:
            metadatas = [{"source": "manual"} for _ in documents]

        try:
            self.collection.add(
                documents=documents,
                metadatas=metadatas,
                ids=ids,
            )
            logger.info("Added %d documents to RAG store", len(documents))
            return len(documents)
        except Exception as e:
            logger.error("Failed to add documents: %s", e)
            return 0

    def get_stats(self) -> dict:
        """Get collection statistics."""
        try:
            return {
                "total_documents": self.collection.count(),
                "chroma_path": self.chroma_path,
                "embedding_model": self.embedding_model,
            }
        except Exception:
            return {"total_documents": 0, "error": "RAG not initialized"}
