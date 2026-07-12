import os
import threading
from sqlalchemy.orm import Session
from models import KBDocument, KBChunk

# Model name - small, fast, good quality for semantic search
MODEL_NAME = 'all-MiniLM-L6-v2'
_model = None
_model_lock = threading.Lock()

# KB directory — defaults to Docker volume path, falls back to local path
KB_DIR = os.getenv(
    "KB_DIR",
    os.path.join(os.path.dirname(__file__), '..', '..', 'data', 'kb_sources')
)

# Category mapping by filename patterns
CATEGORY_MAP = {
    'owasp_a01': ('broken_access_control', 'A01', None),
    'owasp_a02': ('cryptographic_failures', 'A02', None),
    'owasp_a03': ('injection', 'A03', 'CWE-89'),
    'injection':  ('injection', 'A03', 'CWE-89'),
    'python':     ('python_security', None, None),
    'java':       ('java_security', None, None),
    'xss':        ('cross_site_scripting', 'A03', 'CWE-79'),
    'auth':       ('authentication', 'A07', 'CWE-287'),
    'cheat_sheet':('cheat_sheet', None, None),
}


def get_embedding_model():
    """Lazy-load and cache the embedding model (thread-safe)."""
    global _model
    if _model is None:
        with _model_lock:
            if _model is None:
                from sentence_transformers import SentenceTransformer
                print(f"[RAG] Loading embedding model '{MODEL_NAME}'...")
                _model = SentenceTransformer(MODEL_NAME)
                print("[RAG] Embedding model ready.")
    return _model


def chunk_text(text: str, chunk_size: int = 300) -> list[str]:
    """Split text into chunks of ~chunk_size words, preserving paragraph boundaries."""
    paragraphs = [p.strip() for p in text.split('\n\n') if p.strip()]
    chunks = []
    current_words = []

    for para in paragraphs:
        words = para.split()
        if len(current_words) + len(words) > chunk_size and current_words:
            chunks.append(' '.join(current_words))
            current_words = []
        current_words.extend(words)
        if len(current_words) >= chunk_size:
            chunks.append(' '.join(current_words))
            current_words = []

    if current_words:
        chunks.append(' '.join(current_words))

    return [c for c in chunks if len(c.split()) > 10]  # skip tiny fragments


def _get_category_for_file(filename: str):
    """Return (category, owasp_id, cwe_id) based on filename patterns."""
    fname = filename.lower()
    for pattern, meta in CATEGORY_MAP.items():
        if pattern in fname:
            return meta
    return ('general', None, None)


def ingest_document(db: Session, source_name: str, category: str, content: str,
                    owasp_id: str = None, cwe_id: str = None):
    """Chunk a document, embed each chunk, and store in the database."""
    doc = KBDocument(
        source_name=source_name,
        category=category,
        owasp_id=owasp_id,
        cwe_id=cwe_id,
        raw_content_ref=content
    )
    db.add(doc)
    db.flush()

    text_chunks = chunk_text(content)
    embedder = get_embedding_model()

    for chunk in text_chunks:
        embedding = embedder.encode(chunk).tolist()
        kb_chunk = KBChunk(
            kb_id=doc.kb_id,
            chunk_text=chunk,
            embedding=embedding,
            source_name=source_name,
            category=category,
            owasp_id=owasp_id,
            cwe_id=cwe_id,
            token_count=len(chunk.split())
        )
        db.add(kb_chunk)

    db.commit()
    print(f"[RAG] Ingested '{source_name}': {len(text_chunks)} chunks.")


def is_kb_populated(db: Session) -> bool:
    """Return True if there is at least one chunk in the KB."""
    return db.query(KBChunk).limit(1).count() > 0


def ingest_all_kb_sources(db: Session):
    """Ingest all .md and .txt files from KB_DIR into the database."""
    kb_dir = os.path.realpath(KB_DIR)
    if not os.path.isdir(kb_dir):
        print(f"[RAG] KB directory not found: {kb_dir}")
        return

    files = [f for f in os.listdir(kb_dir) if f.endswith(('.md', '.txt'))]
    if not files:
        print(f"[RAG] No source files found in {kb_dir}")
        return

    print(f"[RAG] Ingesting {len(files)} file(s) from {kb_dir}...")
    for filename in files:
        filepath = os.path.join(kb_dir, filename)
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                content = f.read()
            category, owasp_id, cwe_id = _get_category_for_file(filename)
            ingest_document(db, source_name=filename, category=category,
                            content=content, owasp_id=owasp_id, cwe_id=cwe_id)
        except Exception as e:
            print(f"[RAG] Error ingesting {filename}: {e}")

    print("[RAG] KB ingestion complete.")


def retrieve(db: Session, query: str, k: int = 5) -> list[KBChunk]:
    """
    Retrieve top-k most semantically similar chunks for a given query.
    Returns an empty list if the model isn't ready or KB is empty.
    """
    try:
        embedder = get_embedding_model()
        query_embedding = embedder.encode(query).tolist()
        results = (
            db.query(KBChunk)
            .order_by(KBChunk.embedding.l2_distance(query_embedding))
            .limit(k)
            .all()
        )
        return results
    except Exception as e:
        print(f"[RAG] Retrieval error: {e}")
        return []
