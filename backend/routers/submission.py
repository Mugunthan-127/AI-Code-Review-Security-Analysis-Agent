from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Header
from sqlalchemy.orm import Session
from database import get_db
from models import Scan, LanguageEnum, SourceTypeEnum, StatusEnum
from services.validation import validate_code
from services.rag import retrieve
from pydantic import BaseModel
from typing import Optional

router = APIRouter()


class PasteSubmission(BaseModel):
    code: str
    language: str
    session_id: Optional[str] = None


def _build_rag_query(language: str, errors: list) -> str:
    """Build a semantic query string from the language and detected errors."""
    if errors:
        issues = ' '.join(e.get('issue', '') for e in errors[:4])
        return f"{language} security vulnerability {issues}"
    return f"{language} common security vulnerabilities best practices"


def _format_rag_advice(chunks) -> list:
    """Convert KBChunk ORM objects into plain dicts for the API response."""
    seen = set()
    advice = []
    for chunk in chunks:
        # Deduplicate by source + first 60 chars of text
        key = (chunk.source_name, chunk.chunk_text[:60])
        if key in seen:
            continue
        seen.add(key)
        advice.append({
            "source": chunk.source_name,
            "category": chunk.category,
            "owasp_id": chunk.owasp_id,
            "cwe_id": chunk.cwe_id,
            "text": chunk.chunk_text[:400],   # first 400 chars as excerpt
        })
    return advice


@router.post("/paste")
def submit_paste(submission: PasteSubmission, db: Session = Depends(get_db)):
    if submission.language not in [LanguageEnum.python.value, LanguageEnum.java.value]:
        raise HTTPException(status_code=400, detail="Unsupported language. Must be 'python' or 'java'")

    is_valid, error_msg, errors = validate_code(submission.code, submission.language)
    status = StatusEnum.validated if is_valid else StatusEnum.rejected

    scan = Scan(
        language=submission.language,
        source_type=SourceTypeEnum.paste,
        raw_code_ref=submission.code,
        status=status,
        validation_error=error_msg,
        session_id=submission.session_id,
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    # RAG: retrieve relevant security knowledge for this submission
    rag_query = _build_rag_query(submission.language, errors)
    rag_chunks = retrieve(db, rag_query, k=4)
    security_advice = _format_rag_advice(rag_chunks)

    return {
        "status": status,
        "scan_id": str(scan.scan_id),
        "message": "Validation passed." if is_valid else f"Validation failed: {error_msg}",
        "errors": errors,
        "security_advice": security_advice,
    }


@router.post("/upload")
async def submit_upload(
    file: UploadFile = File(...),
    x_session_id: Optional[str] = Header(None),
    db: Session = Depends(get_db)
):
    filename = file.filename
    if filename.endswith(".py"):
        language = LanguageEnum.python
    elif filename.endswith(".java"):
        language = LanguageEnum.java
    else:
        raise HTTPException(status_code=400, detail="Only .py and .java files are supported.")

    code_bytes = await file.read()
    try:
        code_str = code_bytes.decode('utf-8')
    except UnicodeDecodeError:
        raise HTTPException(status_code=400, detail="File must be valid UTF-8 encoded text.")

    is_valid, error_msg, errors = validate_code(code_str, language.value)
    status = StatusEnum.validated if is_valid else StatusEnum.rejected

    scan = Scan(
        language=language,
        source_type=SourceTypeEnum.upload,
        raw_code_ref=code_str,
        status=status,
        validation_error=error_msg,
        session_id=x_session_id,
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    # RAG: retrieve relevant security knowledge
    rag_query = _build_rag_query(language.value, errors)
    rag_chunks = retrieve(db, rag_query, k=4)
    security_advice = _format_rag_advice(rag_chunks)

    return {
        "status": status,
        "scan_id": str(scan.scan_id),
        "message": "Validation passed." if is_valid else f"Validation failed: {error_msg}",
        "errors": errors,
        "security_advice": security_advice,
    }


@router.get("/history")
def get_history(
    session_id: str,
    limit: int = 20,
    db: Session = Depends(get_db)
):
    """Return the last `limit` scans for a given browser session, newest first."""
    scans = (
        db.query(Scan)
        .filter(Scan.session_id == session_id)
        .order_by(Scan.created_at.desc())
        .limit(limit)
        .all()
    )
    return [
        {
            "scan_id": str(s.scan_id),
            "language": s.language.value if s.language else None,
            "source_type": s.source_type.value if s.source_type else None,
            "status": s.status.value if s.status else None,
            "created_at": s.created_at.isoformat() if s.created_at else None,
            "snippet": (s.raw_code_ref or "")[:120],
        }
        for s in scans
    ]
