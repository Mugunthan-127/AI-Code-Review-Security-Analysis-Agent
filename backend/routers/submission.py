from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Header
from sqlalchemy.orm import Session
from database import get_db
from models import Scan, LanguageEnum, SourceTypeEnum, StatusEnum
import json
from services.validation import validate_code
from services.rag import retrieve
from pydantic import BaseModel, constr
from typing import Optional
from langchain_groq import ChatGroq
from langchain_core.messages import SystemMessage, HumanMessage

router = APIRouter()


class PasteSubmission(BaseModel):
    code: constr(min_length=1)
    language: Optional[str] = None
    session_id: Optional[str] = None

class FixRequest(BaseModel):
    finding_id: int

def guess_language(code: str) -> str:
    """Guess if the code is Java or Python based on simple heuristics."""
    java_indicators = ['public class ', 'import java.', 'System.out.print', 'public static void main']
    if any(ind in code for ind in java_indicators):
        return LanguageEnum.java.value
    return LanguageEnum.python.value


def _run_orchestrator(db: Session, scan: Scan, code: str) -> dict:
    from agents.orchestrator import app as langgraph_app
    from models import Finding

    final_state = langgraph_app.invoke({
        "scan_id": str(scan.scan_id),
        "code": code,
        "language": scan.language.value,
        "code_analysis_findings": [],
        "security_findings": [],
        "complexity_findings": [],
        "dependency_findings": [],
        "license_findings": [],
        "findings": [],
    })

    # Read validation state outputted by the graph
    is_valid = final_state.get("is_valid", False)
    scan.status = StatusEnum.completed if is_valid else StatusEnum.rejected
    scan.validation_error = final_state.get("validation_error", "")
    scan.summary_text = final_state.get("summary_text", "")
    scan.risk_score = final_state.get("risk_score")
    db.commit()

    findings_out = []
    if is_valid:
        for f in final_state.get("findings", []):
            finding_db = Finding(
                scan_id=scan.scan_id,
                agent_source=f.get("agent_source"),
                line=f.get("line"),
                column_num=f.get("column"),
                tool=f.get("tool"),
                rule_id=f.get("rule_id"),
                severity=f.get("severity"),
                cvss_score=f.get("cvss_score"),
                category=f.get("category"),
                owasp_type=f.get("owasp_type"),
                title=f.get("title"),
                explanation=f.get("explanation"),
                suggested_fix=f.get("suggested_fix"),
                original_code=f.get("original_code"),
                cwe_id=f.get("cwe_id"),
                grounding_source=f.get("grounding_source"),
                confidence_score=f.get("confidence_score"),
                detected_by=json.dumps(f.get("detected_by", [])) if isinstance(f.get("detected_by"), list) else f.get("detected_by")
            )
            db.add(finding_db)
            db.flush() # get ID
            f["id"] = finding_db.finding_id
            findings_out.append(f)
        db.commit()

    return {
        "is_valid": is_valid,
        "validation_error": scan.validation_error,
        "syntax_errors": final_state.get("syntax_errors", []),
        "summary_text": scan.summary_text,
        "risk_score": final_state.get("risk_score"),
        "findings": findings_out
    }


@router.post("/paste")
def submit_paste(submission: PasteSubmission, db: Session = Depends(get_db)):
    if not submission.code.strip():
        return {
            "status": "rejected",
            "scan_id": None,
            "message": "Validation failed: Code cannot be empty.",
            "syntax_errors": [{"issue": "Code cannot be empty.", "severity": "error"}],
            "summary_text": "Failed to generate summary.",
            "risk_score": 0,
            "findings": []
        }
    # Always auto-detect language to override frontend default
    submission.language = guess_language(submission.code)
        
    if submission.language not in [LanguageEnum.python.value, LanguageEnum.java.value]:
        raise HTTPException(status_code=400, detail="Unsupported language. Must be 'python' or 'java'")

    # Create scan first to get ID
    scan = Scan(
        language=submission.language,
        source_type=SourceTypeEnum.paste,
        raw_code_ref=submission.code,
        status=StatusEnum.analyzed, # Will be updated
        session_id=submission.session_id,
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    orchestrator_res = _run_orchestrator(db, scan, submission.code)

    return {
        "status": scan.status,
        "scan_id": str(scan.scan_id),
        "message": "Validation passed." if orchestrator_res["is_valid"] else f"Validation failed: {orchestrator_res['validation_error']}",
        "syntax_errors": orchestrator_res["syntax_errors"],
        "summary_text": orchestrator_res["summary_text"],
        "risk_score": orchestrator_res["risk_score"],
        "findings": orchestrator_res["findings"]
    }


@router.post("/upload")
async def submit_upload(
    file: UploadFile = File(...),
    x_session_id: Optional[str] = Header(None),
    db: Session = Depends(get_db)
):
    code_bytes = await file.read()
    try:
        code_str = code_bytes.decode('utf-8')
    except UnicodeDecodeError:
        raise HTTPException(status_code=400, detail="File must be valid UTF-8 encoded text.")

    filename = file.filename
    if filename.endswith(".py"):
        language = LanguageEnum.python
    elif filename.endswith(".java"):
        language = LanguageEnum.java
    else:
        # Fall back to automatic detection based on content
        guessed = guess_language(code_str)
        language = LanguageEnum(guessed)

    scan = Scan(
        language=language,
        source_type=SourceTypeEnum.upload,
        raw_code_ref=code_str,
        status=StatusEnum.analyzed,
        session_id=x_session_id,
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    orchestrator_res = _run_orchestrator(db, scan, code_str)

    return {
        "status": scan.status,
        "scan_id": str(scan.scan_id),
        "message": "Validation passed." if orchestrator_res["is_valid"] else f"Validation failed: {orchestrator_res['validation_error']}",
        "syntax_errors": orchestrator_res["syntax_errors"],
        "summary_text": orchestrator_res["summary_text"],
        "risk_score": orchestrator_res["risk_score"],
        "findings": orchestrator_res["findings"]
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
            "risk_score": s.risk_score,
        }
        for s in scans
    ]


@router.post("/{scan_id}/fix")
def apply_fix(scan_id: str, req: FixRequest, db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.scan_id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
        
    from models import Finding
    finding = db.query(Finding).filter(Finding.id == req.finding_id, Finding.scan_id == scan_id).first()
    if not finding or not finding.suggested_fix:
        raise HTTPException(status_code=404, detail="Finding or suggested fix not found")
        
    llm = ChatGroq(model="llama-3.1-8b-instant", temperature=0)
    prompt = f"""You are an automated code patcher.
Apply the following fix to the source code.

SOURCE CODE:
{scan.raw_code_ref}

VULNERABLE SNIPPET TO REPLACE:
{finding.original_code or f"Line {finding.line}"}

SUGGESTED FIX TO APPLY:
{finding.suggested_fix}

Return ONLY the fully patched source code. No markdown formatting blocks around the code (no ```), no preamble, no explanations. Just the raw code.
"""
    try:
        response = llm.invoke([
            SystemMessage(content="You are a strict code patcher. Output ONLY raw source code."),
            HumanMessage(content=prompt)
        ])
        raw_content = response.content
        if isinstance(raw_content, list):
            raw_content = raw_content[0].get("text", "") if isinstance(raw_content[0], dict) else str(raw_content[0])
        patched_code = str(raw_content).strip()
        if patched_code.startswith("```"):
            lines = patched_code.split("\n")
            if len(lines) > 1 and lines[0].startswith("```"):
                patched_code = "\n".join(lines[1:])
            if patched_code.endswith("```"):
                patched_code = patched_code[:-3]
        return {"patched_code": patched_code}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
