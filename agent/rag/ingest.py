"""
One-time HackTricks ingestion script.

Downloads and embeds HackTricks markdown files into the local
ChromaDB vector store for offline RAG at runtime.

Usage:
    python -m agent.rag.ingest --source ./hacktricks_docs/
    python -m agent.rag.ingest --url https://book.hacktricks.wiki
"""

import argparse
import hashlib
import logging
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from agent.config import load_config
from agent.logger import setup_logger
from agent.rag.embedder import RAGStore

logger = logging.getLogger(__name__)


def chunk_text(text: str, chunk_size: int = 500, overlap: int = 50) -> list[str]:
    """
    Split text into chunks of roughly `chunk_size` tokens.
    Uses word boundaries and respects paragraph breaks.

    Args:
        text: Full document text.
        chunk_size: Target chunk size in words (rough token proxy).
        overlap: Words of overlap between chunks.

    Returns:
        List of text chunks.
    """
    words = text.split()
    if len(words) <= chunk_size:
        return [text] if text.strip() else []

    chunks = []
    start = 0
    while start < len(words):
        end = start + chunk_size
        chunk = " ".join(words[start:end])
        if chunk.strip():
            chunks.append(chunk)
        start = end - overlap

    return chunks


def ingest_markdown_directory(
    source_dir: str,
    rag: RAGStore,
    chunk_size: int = 500,
) -> int:
    """
    Ingest all markdown files from a directory into RAG store.

    Args:
        source_dir: Path to directory containing .md files.
        rag: RAGStore instance.
        chunk_size: Words per chunk.

    Returns:
        Total number of chunks ingested.
    """
    source_path = Path(source_dir)
    if not source_path.exists():
        logger.error("Source directory not found: %s", source_dir)
        return 0

    md_files = list(source_path.rglob("*.md"))
    logger.info("Found %d markdown files in %s", len(md_files), source_dir)

    total_chunks = 0

    for md_file in md_files:
        try:
            text = md_file.read_text(encoding="utf-8", errors="ignore")
            if not text.strip() or len(text) < 100:
                continue

            chunks = chunk_text(text, chunk_size=chunk_size)
            if not chunks:
                continue

            # Generate deterministic IDs from content hash
            ids = [
                f"{md_file.stem}_{hashlib.md5(c.encode()).hexdigest()[:8]}"
                for c in chunks
            ]
            metadatas = [
                {"source": str(md_file), "file": md_file.name}
                for _ in chunks
            ]

            added = rag.add_documents(chunks, metadatas=metadatas, ids=ids)
            total_chunks += added
            logger.debug("Ingested %s: %d chunks", md_file.name, added)

        except Exception as e:
            logger.warning("Failed to ingest %s: %s", md_file, e)

    logger.info("Ingestion complete: %d total chunks from %d files",
                total_chunks, len(md_files))
    return total_chunks


def main():
    """CLI entry point for ingestion."""
    setup_logger()

    parser = argparse.ArgumentParser(
        description="Ingest pentest knowledge into RAG store"
    )
    parser.add_argument(
        "--source", "-s",
        required=True,
        help="Path to directory containing markdown files",
    )
    parser.add_argument(
        "--chunk-size", "-c",
        type=int, default=500,
        help="Words per chunk (default: 500)",
    )

    args = parser.parse_args()

    config = load_config()
    rag = RAGStore(config)

    total = ingest_markdown_directory(args.source, rag, args.chunk_size)

    stats = rag.get_stats()
    print(f"\nIngestion complete!")
    print(f"  Chunks added: {total}")
    print(f"  Total docs in store: {stats['total_documents']}")
    print(f"  Store path: {stats['chroma_path']}")


if __name__ == "__main__":
    main()
