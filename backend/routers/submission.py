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


def _run_orchestrator(db: Session, scan: Scan, code: str) -> dict:
    from agents.orchestrator import app as langgraph_app
    from models import Finding

    final_state = langgraph_app.invoke({
        "scan_id": str(scan.scan_id),
        "code": code,
        "language": scan.language.value,
        # Initialise both parallel-agent output keys
        "code_analysis_findings": [],
        "security_findings": [],
        "findings": [],
    })

    scan.summary_text = final_state.get("summary_text", "")
    db.commit()

    findings_out = []
    for f in final_state.get("findings", []):
        finding_db = Finding(
            scan_id=scan.scan_id,
            agent_source=f.get("agent_source"),
            line=f.get("line"),
            column_num=f.get("column"),
            tool=f.get("tool"),
            rule_id=f.get("rule_id"),
            severity=f.get("severity"),
            category=f.get("category"),
            owasp_type=f.get("owasp_type"),
            title=f.get("title"),
            explanation=f.get("explanation"),
            suggested_fix=f.get("suggested_fix"),
            cwe_id=f.get("cwe_id"),
            grounding_source=f.get("grounding_source")
        )
        db.add(finding_db)
        findings_out.append(f)

    db.commit()
    return {
        "summary_text": scan.summary_text,
        "findings": findings_out
    }


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

    result = {
        "status": status,
        "scan_id": str(scan.scan_id),
        "message": "Validation passed." if is_valid else f"Validation failed: {error_msg}",
        "syntax_errors": errors,
    }

    if is_valid:
        orchestrator_res = _run_orchestrator(db, scan, submission.code)
        result["summary_text"] = orchestrator_res["summary_text"]
        result["findings"] = orchestrator_res["findings"]

    return result


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

    result = {
        "status": status,
        "scan_id": str(scan.scan_id),
        "message": "Validation passed." if is_valid else f"Validation failed: {error_msg}",
        "syntax_errors": errors,
    }

    if is_valid:
        orchestrator_res = _run_orchestrator(db, scan, code_str)
        result["summary_text"] = orchestrator_res["summary_text"]
        result["findings"] = orchestrator_res["findings"]

    return result


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
