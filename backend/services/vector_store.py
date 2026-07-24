"""
ChromaDB Vector Store Service
Dedicated vector database layer for the KB knowledge base.
ChromaDB runs embedded (no extra Docker service needed) and persists to disk.
"""
import os
import threading
from typing import Optional

# ChromaDB client singleton
_chroma_client = None
_chroma_lock = threading.Lock()

# Path where ChromaDB persists its data
CHROMA_DB_PATH = os.getenv(
    "CHROMA_DB_PATH",
    os.path.join(os.path.dirname(__file__), '..', '..', 'data', 'chroma_db')
)

KB_COLLECTION_NAME = "kb_chunks"


def get_chroma_client():
    """Lazy-load and cache the ChromaDB client (thread-safe, persistent mode)."""
    global _chroma_client
    if _chroma_client is None:
        with _chroma_lock:
            if _chroma_client is None:
                import chromadb
                db_path = os.path.realpath(CHROMA_DB_PATH)
                os.makedirs(db_path, exist_ok=True)
                print(f"[VectorStore] Initializing ChromaDB at: {db_path}")
                _chroma_client = chromadb.PersistentClient(path=db_path)
                print("[VectorStore] ChromaDB client ready.")
    return _chroma_client


def get_kb_collection():
    """Get (or create) the kb_chunks collection in ChromaDB."""
    client = get_chroma_client()
    # cosine distance is best for semantic similarity with normalized sentence embeddings
    collection = client.get_or_create_collection(
        name=KB_COLLECTION_NAME,
        metadata={"hnsw:space": "cosine"}
    )
    return collection


def upsert_chunk(
    chunk_id: str,
    text: str,
    embedding: list,
    metadata: dict
):
    """
    Add or update a single KB chunk in ChromaDB.
    
    Args:
        chunk_id: Unique identifier for this chunk (UUID string)
        text: The chunk text content
        embedding: 384-dim float list from all-MiniLM-L6-v2
        metadata: Dict with keys like source_name, category, owasp_id, cwe_id, language, severity
    """
    collection = get_kb_collection()
    # ChromaDB metadata values must be str/int/float/bool — convert None to ""
    clean_meta = {k: (v if v is not None else "") for k, v in metadata.items()}
    collection.upsert(
        ids=[chunk_id],
        embeddings=[embedding],
        documents=[text],
        metadatas=[clean_meta]
    )


def query_by_vector(
    embedding: list,
    n_results: int = 20,
    where: Optional[dict] = None
) -> dict:
    """
    Vector similarity search in ChromaDB.
    
    Args:
        embedding: Query embedding vector
        n_results: Number of results to return
        where: ChromaDB metadata filter dict (e.g., {"category": "injection"})
    
    Returns:
        ChromaDB query result dict with ids, documents, metadatas, distances
    """
    collection = get_kb_collection()
    count = collection.count()
    if count == 0:
        return {"ids": [[]], "documents": [[]], "metadatas": [[]], "distances": [[]]}
    
    actual_n = min(n_results, count)
    kwargs = {
        "query_embeddings": [embedding],
        "n_results": actual_n,
        "include": ["documents", "metadatas", "distances"]
    }
    if where:
        kwargs["where"] = where
    
    try:
        return collection.query(**kwargs)
    except Exception as e:
        print(f"[VectorStore] Vector query error: {e}")
        return {"ids": [[]], "documents": [[]], "metadatas": [[]], "distances": [[]]}


def query_by_text(
    query_text: str,
    n_results: int = 20,
    where: Optional[dict] = None
) -> dict:
    """
    Keyword search in ChromaDB using where_document $contains filter.
    Does NOT use ChromaDB's internal embedder — no ONNX model download needed.
    
    Args:
        query_text: Raw text to search for (uses first significant keyword)
        n_results: Number of results to return
        where: ChromaDB metadata filter dict
    
    Returns:
        Dict with ids, documents, metadatas (no distances for keyword search)
    """
    collection = get_kb_collection()
    count = collection.count()
    if count == 0:
        return {"ids": [[]], "documents": [[]], "metadatas": [[]], "distances": [[]]}

    # Extract the most meaningful keyword (longest word that's alphabetic)
    words = [w for w in query_text.split() if w.isalpha() and len(w) > 3]
    if not words:
        return {"ids": [[]], "documents": [[]], "metadatas": [[]], "distances": [[]]}
    # Use the longest word as the keyword anchor
    keyword = max(words, key=len)

    actual_n = min(n_results, count)
    kwargs = {
        "where_document": {"$contains": keyword},
        "limit": actual_n,
        "include": ["documents", "metadatas"]
    }
    if where:
        kwargs["where"] = where

    try:
        result = collection.get(**kwargs)
        # Normalize to same shape as query() results (no distances for get())
        ids = result.get("ids", [])
        docs = result.get("documents", [])
        metas = result.get("metadatas", [])
        return {
            "ids": [ids],
            "documents": [docs],
            "metadatas": [metas],
            "distances": [[0.5] * len(ids)]  # neutral distance placeholder
        }
    except Exception as e:
        print(f"[VectorStore] Keyword search error: {e}")
        return {"ids": [[]], "documents": [[]], "metadatas": [[]], "distances": [[]]}


def count_chunks() -> int:
    """Return total number of chunks stored in ChromaDB."""
    try:
        return get_kb_collection().count()
    except Exception:
        return 0


def get_collection_stats() -> dict:
    """Return detailed stats about the ChromaDB collection."""
    try:
        collection = get_kb_collection()
        total = collection.count()
        
        # Sample some metadata to get category breakdown
        sample_size = min(total, 500)
        categories = {}
        languages = {}
        
        if sample_size > 0:
            results = collection.get(
                limit=sample_size,
                include=["metadatas"]
            )
            for meta in results.get("metadatas", []):
                cat = meta.get("category", "unknown")
                lang = meta.get("language", "")
                categories[cat] = categories.get(cat, 0) + 1
                if lang:
                    languages[lang] = languages.get(lang, 0) + 1
        
        return {
            "total_chunks": total,
            "collection_name": KB_COLLECTION_NAME,
            "chroma_db_path": os.path.realpath(CHROMA_DB_PATH),
            "categories": categories,
            "languages": languages,
        }
    except Exception as e:
        return {"error": str(e), "total_chunks": 0}


def delete_all_chunks():
    """Delete and recreate the kb_chunks collection (for re-ingestion)."""
    client = get_chroma_client()
    try:
        client.delete_collection(KB_COLLECTION_NAME)
        print("[VectorStore] Deleted existing kb_chunks collection.")
    except Exception:
        pass
    # Recreate empty collection
    get_kb_collection()
    print("[VectorStore] Re-created empty kb_chunks collection.")
