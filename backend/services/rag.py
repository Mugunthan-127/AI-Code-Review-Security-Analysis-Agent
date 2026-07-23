import os
import re
import threading
import json
import hashlib
from sqlalchemy.orm import Session
from models import KBDocument, KBChunk

try:
    import redis
    REDIS_URL = os.getenv("REDIS_URL", None) # Default None to skip if not set
    redis_client = redis.Redis.from_url(REDIS_URL) if REDIS_URL else None
    if redis_client:
        redis_client.ping()
except Exception as e:
    print(f"[RAG] Redis cache unavailable: {e}")
    redis_client = None

# Model name - small, fast, good quality for semantic search
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

def get_cached_embedding(text: str) -> list[float]:
    """Get embedding from Redis cache if available, else compute and cache."""
    # Create deterministic hash for text
    text_hash = hashlib.md5(text.encode('utf-8')).hexdigest()
    cache_key = f"emb:{MODEL_NAME}:{text_hash}"
    
    if redis_client:
        try:
            cached = redis_client.get(cache_key)
            if cached:
                print(f"[RAG] Cache hit for embedding")
                return json.loads(cached)
        except Exception:
            pass # fallback to computing
            
    # Cache miss or redis unavailable, compute it
    embedder = get_embedding_model()
    embedding = embedder.encode(text).tolist()
    
    if redis_client:
        try:
            # Cache for 24 hours
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


def chunk_text(text: str, chunk_size: int = 300) -> list[str]:
    """
    Split text recursively by paragraphs, then sentences, then words
    to ensure we don't break semantic boundaries unnecessarily.
    """
    chunks = []
    
    # 1. Split by paragraphs
    paragraphs = re.split(r'\n\n+', text)
    
    current_words = []
    for para in paragraphs:
        para = para.strip()
        if not para:
            continue
            
        # 2. If a paragraph is huge, split by sentences
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

    return [c for c in chunks if len(c.split()) > 10]  # skip tiny fragments


def _get_category_for_file(filename: str):
    """Return (category, owasp_id, cwe_id, language, severity) based on filename patterns."""
    fname = filename.lower()
    for pattern, meta in CATEGORY_MAP.items():
        if pattern in fname:
            return meta
    return ('general', None, None, None, None)


def ingest_document(db: Session, source_name: str, category: str, content: str,
                    owasp_id: str = None, cwe_id: str = None, language: str = None, severity: str = None):
    """Chunk a document, embed each chunk, and store in the database."""
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

    for chunk in text_chunks:
        embedding = get_cached_embedding(chunk)
        kb_chunk = KBChunk(
            kb_id=doc.kb_id,
            chunk_text=chunk,
            embedding=embedding,
            source_name=source_name,
            category=category,
            owasp_id=owasp_id,
            cwe_id=cwe_id,
            language=language,
            severity=severity,
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
            category, owasp_id, cwe_id, language, severity = _get_category_for_file(filename)
            ingest_document(db, source_name=filename, category=category,
                            content=content, owasp_id=owasp_id, cwe_id=cwe_id,
                            language=language, severity=severity)
        except Exception as e:
            print(f"[RAG] Error ingesting {filename}: {e}")

    print("[RAG] KB ingestion complete.")


def _apply_metadata_filters(query, category=None, language=None, severity=None, owasp_id=None, cwe_id=None):
    from sqlalchemy import or_
    
    if category:
        query = query.filter(KBChunk.category == category)
    if language:
        # Match specific language or docs that apply to all languages (None)
        query = query.filter(or_(KBChunk.language == language, KBChunk.language == None))
    if severity:
        # Severity ranking map to filter >= severity
        sev_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1}
        target_rank = sev_rank.get(severity.lower(), 0)
        
        # In SQL, we can't easily do a mapped comparison without a CASE WHEN, 
        # so we build a list of acceptable severities.
        valid_sevs = [s for s, r in sev_rank.items() if r >= target_rank]
        query = query.filter(or_(KBChunk.severity.in_(valid_sevs), KBChunk.severity == None))
        
    if owasp_id:
        query = query.filter(KBChunk.owasp_id == owasp_id)
    if cwe_id:
        query = query.filter(KBChunk.cwe_id == cwe_id)
        
    return query


def retrieve(db: Session, query: str, k: int = 5, category: str = None, language: str = None, severity: str = None, owasp_id: str = None, cwe_id: str = None) -> list[KBChunk]:
    """
    Retrieve top-k most semantically similar chunks for a given query,
    using a Hybrid Fetch-then-Re-rank strategy.
    """
    try:
        from sqlalchemy import func
        fetch_k = max(20, k * 3)
        
        # Apply metadata filters to base query
        base_query = db.query(KBChunk)
        base_query = _apply_metadata_filters(base_query, category, language, severity, owasp_id, cwe_id)

        # -------------------------------------------------------------
        # Step 1: Hybrid Fetch (Vector Search + Keyword Search)
        # -------------------------------------------------------------
        
        # 1a. Vector Search
        query_embedding = get_cached_embedding(query)
        vector_candidates = (
            base_query
            .order_by(KBChunk.embedding.l2_distance(query_embedding))
            .limit(fetch_k)
            .all()
        )
        
        # 1b. Keyword Search (BM25 approximation via Postgres Full Text Search)
        # We transform spaces in the query into '&' for tsquery to match all terms
        query_terms = ' & '.join([w for w in query.split() if w.isalnum()])
        if not query_terms:
            query_terms = query # fallback
            
        keyword_candidates = []
        if query_terms:
            tsquery = func.plainto_tsquery('english', query)
            tsvector = func.to_tsvector('english', KBChunk.chunk_text)
            keyword_candidates = (
                base_query
                .filter(tsvector.op("@@")(tsquery))
                .order_by(func.ts_rank(tsvector, tsquery).desc())
                .limit(fetch_k)
                .all()
            )
            
        # Combine and deduplicate candidates
        candidate_map = {}
        for c in vector_candidates + keyword_candidates:
            candidate_map[c.chunk_id] = c
            
        candidates = list(candidate_map.values())
        
        if not candidates:
            return []
            
        # -------------------------------------------------------------
        # Step 2: Re-rank candidates using Cross-Encoder (highly accurate)
        # -------------------------------------------------------------
        cross_encoder = get_cross_encoder()
        pairs = [[query, chunk.chunk_text] for chunk in candidates]
        scores = cross_encoder.predict(pairs)
        
        scored_candidates = list(zip(candidates, scores))
        scored_candidates.sort(key=lambda x: x[1], reverse=True)
        
        # -------------------------------------------------------------
        # Step 3: Return top-k
        # -------------------------------------------------------------
        return [item[0] for item in scored_candidates[:k]]
        
    except Exception as e:
        print(f"[RAG] Retrieval error: {e}")
        return []
