from fastapi import APIRouter, Depends, BackgroundTasks, HTTPException
from sqlalchemy.orm import Session
from database import get_db
from pydantic import BaseModel
from typing import Optional
from services.rag import retrieve
from services.vector_store import get_collection_stats, delete_all_chunks

router = APIRouter()


class RetrieveRequest(BaseModel):
    query: str
    k: int = 5
    category: Optional[str] = None
    language: Optional[str] = None
    severity: Optional[str] = None
    owasp_id: Optional[str] = None
    cwe_id: Optional[str] = None


@router.post("/retrieve")
def retrieve_kb(req: RetrieveRequest, db: Session = Depends(get_db)):
    """
    Retrieve top-k most semantically similar chunks from ChromaDB for a query.
    Supports optional filters: category, language, severity, owasp_id, cwe_id.
    """
    chunks = retrieve(
        db=db,
        query=req.query,
        k=req.k,
        category=req.category,
        language=req.language,
        severity=req.severity,
        owasp_id=req.owasp_id,
        cwe_id=req.cwe_id
    )

    results = []
    for chunk in chunks:
        results.append({
            "source": chunk.source_name,
            "category": chunk.category,
            "owasp_id": chunk.owasp_id,
            "cwe_id": chunk.cwe_id,
            "language": chunk.language,
            "severity": chunk.severity,
            "text": chunk.chunk_text,
            "token_count": chunk.token_count,
            "score": round(getattr(chunk, "score", 0.0), 4),
        })

    return {"results": results, "total": len(results)}


@router.get("/stats")
def kb_stats():
    """
    Return ChromaDB vector store statistics:
    total chunks, category breakdown, language breakdown, collection info.
    """
    stats = get_collection_stats()
    return stats


@router.post("/reset")
def reset_kb(background_tasks: BackgroundTasks, db: Session = Depends(get_db)):
    """
    Delete all KB chunks from ChromaDB and re-ingest from kb_sources directory.
    Also clears KBDocument records from PostgreSQL.
    Runs ingestion in the background so the response returns immediately.
    """
    from models import KBDocument
    from services.rag import ingest_all_kb_sources

    # Clear ChromaDB collection
    delete_all_chunks()

    # Clear Postgres KBDocument tracking records
    db.query(KBDocument).delete()
    db.commit()

    # Re-ingest in background
    def _re_ingest():
        from database import SessionLocal
        new_db = SessionLocal()
        try:
            ingest_all_kb_sources(new_db)
        finally:
            new_db.close()

    background_tasks.add_task(_re_ingest)

    return {
        "status": "reset_started",
        "message": "ChromaDB collection cleared. Re-ingestion started in background."
    }
