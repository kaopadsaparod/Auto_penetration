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
    Filters out extremely long words to prevent binary/base64 block embedding errors.

    Args:
        text: Full document text.
        chunk_size: Target chunk size in words (rough token proxy).
        overlap: Words of overlap between chunks.

    Returns:
        List of text chunks.
    """
    # Split and clean words: filter out very long strings (base64, hex dumps, etc.)
    words = text.split()
    words = [w for w in words if len(w) < 100]

    if len(words) <= chunk_size:
        cleaned_text = " ".join(words)
        return [cleaned_text] if cleaned_text.strip() else []

    chunks = []
    start = 0
    while start < len(words):
        end = start + chunk_size
        chunk = " ".join(words[start:end])
        if chunk.strip():
            # Cap character length to be completely safe against context window errors
            if len(chunk) > 8000:
                chunk = chunk[:8000]
            chunks.append(chunk)
        start = end - overlap

    return chunks


def ingest_markdown_directory(
    source_dir: str,
    rag: RAGStore,
    chunk_size: int = 500,
) -> int:
    """
    Ingest all markdown files from a directory into RAG store in batches.

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
    
    # Accumulators for batching
    batch_chunks = []
    batch_metadatas = []
    batch_ids = []
    batch_size = 15

    for md_file in md_files:
        try:
            text = md_file.read_text(encoding="utf-8", errors="ignore")
            if not text.strip() or len(text) < 100:
                continue

            chunks = chunk_text(text, chunk_size=chunk_size)
            if not chunks:
                continue

            for c in chunks:
                chunk_id = f"{md_file.stem}_{hashlib.md5(c.encode()).hexdigest()[:8]}"
                batch_chunks.append(c)
                batch_metadatas.append({"source": str(md_file), "file": md_file.name})
                batch_ids.append(chunk_id)

            if len(batch_chunks) >= batch_size:
                added = rag.add_documents(batch_chunks, metadatas=batch_metadatas, ids=batch_ids)
                total_chunks += added
                logger.info("Batch added %d documents. Total ingested so far: %d", added, total_chunks)
                batch_chunks = []
                batch_metadatas = []
                batch_ids = []

        except Exception as e:
            logger.warning("Failed to process %s: %s", md_file, e)

    # Ingest any remaining documents
    if batch_chunks:
        added = rag.add_documents(batch_chunks, metadatas=batch_metadatas, ids=batch_ids)
        total_chunks += added
        logger.info("Final batch added %d documents. Total: %d", added, total_chunks)

    logger.info("Ingestion complete: %d total chunks from %d files",
                total_chunks, len(md_files))
    return total_chunks


def download_and_extract_hacktricks() -> str:
    """Download HackTricks master branch ZIP and extract it to data/hacktricks_docs."""
    import requests
    import zipfile
    import io

    url = "https://github.com/HackTricks-wiki/hacktricks/archive/refs/heads/master.zip"
    dest_dir = Path("./data/hacktricks_docs")
    dest_dir.mkdir(parents=True, exist_ok=True)

    logger.info("Downloading HackTricks master ZIP from %s ...", url)
    response = requests.get(url, timeout=120)
    response.raise_for_status()

    logger.info("Extracting ZIP contents...")
    with zipfile.ZipFile(io.BytesIO(response.content)) as zip_ref:
        zip_ref.extractall(dest_dir)

    logger.info("HackTricks successfully extracted to %s", dest_dir)
    return str(dest_dir)


def main():
    """CLI entry point for ingestion."""
    setup_logger()

    parser = argparse.ArgumentParser(
        description="Ingest pentest knowledge into RAG store"
    )
    parser.add_argument(
        "--source", "-s",
        required=False,
        help="Path to directory containing markdown files",
    )
    parser.add_argument(
        "--download", "-d",
        action="store_true",
        help="Download latest HackTricks documentation ZIP automatically",
    )
    parser.add_argument(
        "--chunk-size", "-c",
        type=int, default=500,
        help="Words per chunk (default: 500)",
    )

    args = parser.parse_args()

    if not args.source and not args.download:
        parser.error("At least one of --source (-s) or --download (-d) is required")

    config = load_config()
    rag = RAGStore(config)

    source_dir = args.source
    if args.download:
        try:
            source_dir = download_and_extract_hacktricks()
        except Exception as e:
            logger.critical("Failed to download and extract HackTricks: %s", e)
            sys.exit(1)

    total = ingest_markdown_directory(source_dir, rag, args.chunk_size)

    stats = rag.get_stats()
    print(f"\nIngestion complete!")
    print(f"  Chunks added: {total}")
    print(f"  Total docs in store: {stats['total_documents']}")
    print(f"  Store path: {stats['chroma_path']}")


if __name__ == "__main__":
    main()
