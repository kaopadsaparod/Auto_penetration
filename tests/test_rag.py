"""
Tests for local RAG (ChromaDB + Mocked Ollama Embeddings).
"""
import pytest
import tempfile
import hashlib
from unittest.mock import patch
from agent.rag.embedder import RAGStore
from chromadb.utils.embedding_functions import OllamaEmbeddingFunction

class DummyEmbeddingFunction(OllamaEmbeddingFunction):
    def __init__(self):
        super().__init__(url="http://localhost:11434", model_name="nomic-embed-text")
    
    def _embed(self, text: str) -> list[float]:
        import re
        import math
        import random
        # Tokenize words, converting to lowercase
        words = re.findall(r'\w+(?:-\w+)*', text.lower())
        if not words:
            return [0.0] * 768
        
        # Accumulate deterministic vectors for each unique token/word
        vector = [0.0] * 768
        for word in words:
            rng = random.Random(word)
            word_vector = [rng.uniform(-1.0, 1.0) for _ in range(768)]
            for i in range(768):
                vector[i] += word_vector[i]
        
        # Normalize vector to unit length
        norm = math.sqrt(sum(x * x for x in vector))
        if norm > 0:
            vector = [x / norm for x in vector]
        return vector

    def __call__(self, *args, **kwargs):
        texts = kwargs.get("input") or (args[0] if args else [])
        if isinstance(texts, str):
            texts = [texts]
        return [self._embed(t) for t in texts]
        
    def embed_query(self, *args, **kwargs):
        query = kwargs.get("input") or (args[0] if args else "")
        if isinstance(query, list):
            query = query[0] if query else ""
        # ChromaDB query_embeddings expects a list of sequence of floats, or list of list of floats
        return [self._embed(query)]

@pytest.fixture
def mock_embedding_function():
    """Mock OllamaEmbeddingFunction to return dummy embeddings offline."""
    with patch("chromadb.utils.embedding_functions.OllamaEmbeddingFunction", return_value=DummyEmbeddingFunction()):
        yield

@pytest.fixture
def rag_store(mock_embedding_function):
    """Create a temporary offline RAGStore."""
    # Use ignore_cleanup_errors=True to prevent Windows file locking issues during test teardown
    tmpdir_obj = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
    tmpdir = tmpdir_obj.name
    try:
        config = {
            "rag": {
                "chroma_path": tmpdir,
                "embedding_model": "mock-model",
                "top_k": 1  # top_k=1 to ensure we get the best nearest neighbor match
            },
            "llm": {
                "ollama_host": "http://localhost:11434"
            }
        }
        store = RAGStore(config)
        yield store
    finally:
        try:
            # Attempt normal cleanup, but ignore if Windows locks the file
            tmpdir_obj.cleanup()
        except Exception:
            pass

class TestRAGStore:
    def test_add_and_retrieve_service(self, rag_store):
        # Initial empty check
        assert rag_store.get_stats()["total_documents"] == 0

        # Add documents with distinct content
        docs = [
            "Apache HTTP Server 2.4.49 path traversal and exploitation techniques.",
            "Nginx 1.18.0 request smuggling vulnerabilities.",
            "OpenSSH 8.9 unauthenticated remote code execution details."
        ]
        metadatas = [
            {"source": "test", "file": "apache.md"},
            {"source": "test", "file": "nginx.md"},
            {"source": "test", "file": "openssh.md"}
        ]
        ids = ["doc_apache", "doc_nginx", "doc_openssh"]

        added = rag_store.add_documents(docs, metadatas=metadatas, ids=ids)
        assert added == 3
        assert rag_store.get_stats()["total_documents"] == 3

        # Query service context specifically targeting Apache
        context = rag_store.get_context_for_service("apache", "2.4.49")
        assert "Apache" in context
        assert "traversal" in context

        # Query different service specifically targeting Nginx
        nginx_context = rag_store.get_context_for_service("nginx", "1.18.0")
        assert "Nginx" in nginx_context
        assert "smuggling" in nginx_context

    def test_get_context_for_cve(self, rag_store):
        docs = [
            "CVE-2021-41773 Apache CGI exploitation using URL encoding.",
            "CVE-2020-0601 CryptoAPI spoofing vulnerability details."
        ]
        rag_store.add_documents(docs)

        context = rag_store.get_context_for_cve("CVE-2021-41773")
        assert "Apache" in context
        assert "CGI" in context

    def test_empty_query_fallback(self, rag_store):
        # Assert grace under empty collection or failed query
        assert rag_store.get_context_for_service("nonexistent") == ""
        assert rag_store.get_context_for_cve("CVE-0000-0000") == ""
