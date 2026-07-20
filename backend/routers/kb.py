from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from database import get_db
from pydantic import BaseModel
from typing import Optional
from services.rag import retrieve

router = APIRouter()

class RetrieveRequest(BaseModel):
    query: str
    k: int = 5
    category: Optional[str] = None
    owasp_id: Optional[str] = None
    cwe_id: Optional[str] = None

@router.post("/retrieve")
def retrieve_kb(req: RetrieveRequest, db: Session = Depends(get_db)):
    """
    Retrieve top-k most semantically similar chunks for a given query.
    """
    chunks = retrieve(
        db=db,
        query=req.query,
        k=req.k,
        category=req.category,
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
            "text": chunk.chunk_text,
            "token_count": chunk.token_count
        })
        
    return {"results": results}
