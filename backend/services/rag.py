"""
RAG Service — Retrieval-Augmented Generation
Uses ChromaDB as the dedicated vector store for KB chunk storage and retrieval.
PostgreSQL (via SQLAlchemy) still handles KBDocument ingestion-tracking metadata.
Redis is used to cache embeddings (optional, graceful fallback if unavailable).
"""
import os
import re
import uuid
import threading
import json
import hashlib
from sqlalchemy.orm import Session
from models import KBDocument

try:
    import redis
    REDIS_URL = os.getenv("REDIS_URL", None)
    redis_client = redis.Redis.from_url(REDIS_URL) if REDIS_URL else None
    if redis_client:
        redis_client.ping()
except Exception as e:
    print(f"[RAG] Redis cache unavailable: {e}")
    redis_client = None

# Embedding model — small, fast, 384-dim, great for semantic search
MODEL_NAME = 'all-MiniLM-L6-v2'
_model = None
_model_lock = threading.Lock()

CROSS_ENCODER_MODEL_NAME = 'cross-encoder/ms-marco-MiniLM-L-6-v2'
_cross_encoder = None
_ce_lock = threading.Lock()

# KB directory — defaults to Docker volume path, falls back to local path
KB_DIR = os.getenv(
    "KB_DIR",
    os.path.join(os.path.dirname(__file__), '..', '..', 'data', 'kb_sources')
)

# Category mapping by filename patterns
# Maps filename prefix -> (category, owasp_id, cwe_id, language, severity)
CATEGORY_MAP = {
    'owasp_a01': ('broken_access_control',       'A01', None,      None,     'medium'),
    'owasp_a02': ('cryptographic_failures',      'A02', 'CWE-327', None,     'high'),
    'owasp_a03': ('injection',                   'A03', 'CWE-89',  None,     'high'),
    'owasp_a04': ('insecure_design',             'A04', None,      None,     'medium'),
    'owasp_a05': ('security_misconfiguration',   'A05', None,      None,     'medium'),
    'owasp_a06': ('vulnerable_components',       'A06', None,      None,     'medium'),
    'owasp_a07': ('authentication_failures',     'A07', 'CWE-287', None,     'high'),
    'owasp_a08': ('data_integrity_failures',     'A08', 'CWE-502', None,     'high'),
    'owasp_a09': ('logging_failures',            'A09', None,      None,     'low'),
    'owasp_a10': ('ssrf',                        'A10', 'CWE-918', None,     'medium'),
    'injection': ('injection',                   'A03', 'CWE-89',  None,     'high'),
    'cert_python':('cert_guidelines',            None,  None,      'python', 'medium'),
    'cert_java':  ('cert_guidelines',            None,  None,      'java',   'medium'),
    'python':     ('python_security',            None,  None,      'python', 'medium'),
    'java':       ('java_security',              None,  None,      'java',   'medium'),
    'xss':        ('cross_site_scripting',       'A03', 'CWE-79',  None,     'high'),
    'auth':       ('authentication',             'A07', 'CWE-287', None,     'high'),
    'cheat_sheet':('cheat_sheet',                None,  None,      None,     'medium'),
    'cwe':        ('cwe_reference',              None,  None,      None,     'medium'),
    'csrf':       ('csrf',                       'A01', 'CWE-352', None,     'high'),
    'oracle':     ('oracle_docs',                None,  None,      'java',   'low'),
    'spring':     ('spring_security',            None,  None,      'java',   'medium'),
    'microsoft':  ('microsoft_secure_coding',    None,  None,      None,     'medium'),
    'nist':       ('nist_guidelines',            None,  None,      None,     'medium'),
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


def get_cached_embedding(text: str) -> list:
    """Get embedding from Redis cache if available, else compute and cache."""
    text_hash = hashlib.md5(text.encode('utf-8')).hexdigest()
    cache_key = f"emb:{MODEL_NAME}:{text_hash}"

    if redis_client:
        try:
            cached = redis_client.get(cache_key)
            if cached:
                return json.loads(cached)
        except Exception:
            pass

    embedder = get_embedding_model()
    embedding = embedder.encode(text).tolist()

    if redis_client:
        try:
            redis_client.setex(cache_key, 86400, json.dumps(embedding))
        except Exception:
            pass

    return embedding


def get_cross_encoder():
    """Lazy-load and cache the cross-encoder model (thread-safe)."""
    global _cross_encoder
    if _cross_encoder is None:
        with _ce_lock:
            if _cross_encoder is None:
                from sentence_transformers import CrossEncoder
                print(f"[RAG] Loading cross-encoder model '{CROSS_ENCODER_MODEL_NAME}'...")
                _cross_encoder = CrossEncoder(CROSS_ENCODER_MODEL_NAME)
                print("[RAG] Cross-encoder model ready.")
    return _cross_encoder


def chunk_text(text: str, chunk_size: int = 300) -> list:
    """
    Split text recursively by paragraphs, then sentences, then words
    to ensure we don't break semantic boundaries unnecessarily.
    """
    chunks = []
    paragraphs = re.split(r'\n\n+', text)

    current_words = []
    for para in paragraphs:
        para = para.strip()
        if not para:
            continue

        if len(para.split()) > chunk_size:
            sentences = re.split(r'(?<=[.!?])\s+', para)
            for sentence in sentences:
                sentence_words = sentence.split()
                if len(current_words) + len(sentence_words) > chunk_size and current_words:
                    chunks.append(' '.join(current_words))
                    current_words = []
                current_words.extend(sentence_words)
        else:
            para_words = para.split()
            if len(current_words) + len(para_words) > chunk_size and current_words:
                chunks.append(' '.join(current_words))
                current_words = []
            current_words.extend(para_words)

    if current_words:
        chunks.append(' '.join(current_words))

    return [c for c in chunks if len(c.split()) > 10]


def _get_category_for_file(filename: str):
    """Return (category, owasp_id, cwe_id, language, severity) based on filename."""
    fname = filename.lower()
    for pattern, meta in CATEGORY_MAP.items():
        if pattern in fname:
            return meta
    return ('general', None, None, None, None)


def ingest_document(
    db: Session,
    source_name: str,
    category: str,
    content: str,
    owasp_id: str = None,
    cwe_id: str = None,
    language: str = None,
    severity: str = None
):
    """
    Chunk a document, embed each chunk, and store in ChromaDB.
    Also records the document metadata in PostgreSQL (KBDocument table).
    """
    from services.vector_store import upsert_chunk

    # Record the document in Postgres for tracking
    doc = KBDocument(
        source_name=source_name,
        category=category,
        owasp_id=owasp_id,
        cwe_id=cwe_id,
        language=language,
        severity=severity,
        raw_content_ref=content
    )
    db.add(doc)
    db.flush()

    text_chunks = chunk_text(content)

    for i, chunk in enumerate(text_chunks):
        embedding = get_cached_embedding(chunk)
        # Use a deterministic UUID based on source + index so re-ingestion is idempotent
        chunk_id = str(uuid.uuid5(uuid.NAMESPACE_DNS, f"{source_name}::chunk::{i}"))
        metadata = {
            "source_name": source_name,
            "category": category,
            "owasp_id": owasp_id or "",
            "cwe_id": cwe_id or "",
            "language": language or "",
            "severity": severity or "",
            "token_count": len(chunk.split()),
            "kb_doc_id": str(doc.kb_id),
        }
        upsert_chunk(chunk_id, chunk, embedding, metadata)

    db.commit()
    print(f"[RAG] Ingested '{source_name}': {len(text_chunks)} chunks → ChromaDB.")


def is_kb_populated(db: Session) -> bool:
    """Return True if ChromaDB has at least one chunk stored."""
    from services.vector_store import count_chunks
    return count_chunks() > 0


def ingest_all_kb_sources(db: Session):
    """Ingest all .md and .txt files from KB_DIR into ChromaDB."""
    kb_dir = os.path.realpath(KB_DIR)
    if not os.path.isdir(kb_dir):
        print(f"[RAG] KB directory not found: {kb_dir}")
        return

    files = [f for f in os.listdir(kb_dir) if f.endswith(('.md', '.txt'))]
    if not files:
        print(f"[RAG] No source files found in {kb_dir}")
        return

    print(f"[RAG] Ingesting {len(files)} file(s) from {kb_dir} into ChromaDB...")
    for filename in files:
        filepath = os.path.join(kb_dir, filename)
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                content = f.read()
            category, owasp_id, cwe_id, language, severity = _get_category_for_file(filename)
            ingest_document(
                db,
                source_name=filename,
                category=category,
                content=content,
                owasp_id=owasp_id,
                cwe_id=cwe_id,
                language=language,
                severity=severity
            )
        except Exception as e:
            print(f"[RAG] Error ingesting {filename}: {e}")

    print("[RAG] KB ingestion into ChromaDB complete.")


def _build_chroma_where_filter(
    category: str = None,
    language: str = None,
    severity: str = None,
    owasp_id: str = None,
    cwe_id: str = None
) -> dict:
    """
    Build a ChromaDB `where` filter dict from optional metadata constraints.
    Uses $and/$or operators for compound filters.
    Returns None if no filters apply.
    """
    conditions = []

    if category:
        conditions.append({"category": {"$eq": category}})

    if language:
        # Match the specific language OR docs that apply to all (empty string = any)
        conditions.append({
            "$or": [
                {"language": {"$eq": language}},
                {"language": {"$eq": ""}}
            ]
        })

    if severity:
        sev_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1}
        target_rank = sev_rank.get(severity.lower(), 0)
        valid_sevs = [s for s, r in sev_rank.items() if r >= target_rank] + [""]
        conditions.append({"severity": {"$in": valid_sevs}})

    if owasp_id:
        conditions.append({"owasp_id": {"$eq": owasp_id}})

    if cwe_id:
        conditions.append({"cwe_id": {"$eq": cwe_id}})

    if not conditions:
        return None
    if len(conditions) == 1:
        return conditions[0]
    return {"$and": conditions}


def retrieve(
    db: Session,
    query: str,
    k: int = 5,
    category: str = None,
    language: str = None,
    severity: str = None,
    owasp_id: str = None,
    cwe_id: str = None
) -> list:
    """
    Retrieve top-k most semantically similar KB chunks for a given query.
    
    Strategy:
    1. Hybrid Fetch — vector similarity search + keyword search via ChromaDB
    2. Deduplicate candidates
    3. Re-rank with Cross-Encoder for precise scoring
    4. Return top-k
    
    Returns a list of SimpleNamespace objects with .chunk_text, .source_name,
    .category, .owasp_id, .cwe_id, .language, .severity, .token_count, .score
    """
    from types import SimpleNamespace
    from services.vector_store import query_by_vector, query_by_text

    try:
        fetch_k = max(20, k * 3)
        where_filter = _build_chroma_where_filter(category, language, severity, owasp_id, cwe_id)

        # ----------------------------------------------------------------
        # Step 1a: Vector similarity search in ChromaDB
        # ----------------------------------------------------------------
        query_embedding = get_cached_embedding(query)
        vector_results = query_by_vector(query_embedding, n_results=fetch_k, where=where_filter)

        # ----------------------------------------------------------------
        # Step 1b: Keyword / text-based search in ChromaDB
        # ----------------------------------------------------------------
        keyword_results = query_by_text(query, n_results=fetch_k, where=where_filter)

        # ----------------------------------------------------------------
        # Combine & deduplicate by chunk ID
        # ----------------------------------------------------------------
        candidate_map = {}

        def _add_results(results: dict):
            ids = results.get("ids", [[]])[0]
            docs = results.get("documents", [[]])[0]
            metas = results.get("metadatas", [[]])[0]
            distances = results.get("distances", [[]])[0]

            for chunk_id, text, meta, dist in zip(ids, docs, metas, distances):
                if chunk_id not in candidate_map:
                    candidate_map[chunk_id] = SimpleNamespace(
                        chunk_id=chunk_id,
                        chunk_text=text,
                        source_name=meta.get("source_name", ""),
                        category=meta.get("category", ""),
                        owasp_id=meta.get("owasp_id") or None,
                        cwe_id=meta.get("cwe_id") or None,
                        language=meta.get("language") or None,
                        severity=meta.get("severity") or None,
                        token_count=meta.get("token_count", 0),
                        score=1.0 - float(dist),  # cosine: distance → similarity
                    )

        _add_results(vector_results)
        _add_results(keyword_results)

        candidates = list(candidate_map.values())
        if not candidates:
            return []

        # ----------------------------------------------------------------
        # Step 2: Re-rank with Cross-Encoder
        # ----------------------------------------------------------------
        cross_encoder = get_cross_encoder()
        pairs = [[query, c.chunk_text] for c in candidates]
        scores = cross_encoder.predict(pairs)

        scored = sorted(zip(candidates, scores), key=lambda x: x[1], reverse=True)

        # ----------------------------------------------------------------
        # Step 3: Return top-k with updated score
        # ----------------------------------------------------------------
        top_k = []
        for chunk, ce_score in scored[:k]:
            chunk.score = float(ce_score)
            top_k.append(chunk)

        return top_k

    except Exception as e:
        print(f"[RAG] Retrieval error: {e}")
        return []
