from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Header
from sqlalchemy.orm import Session
from database import get_db
from models import Scan, LanguageEnum, SourceTypeEnum, StatusEnum
import json
from services.validation import validate_code
from services.rag import retrieve
from pydantic import BaseModel, Field
from typing import Optional
from langchain_groq import ChatGroq
from langchain_core.messages import SystemMessage, HumanMessage
import uuid

router = APIRouter()


class PasteSubmission(BaseModel):
    code: str = Field(..., min_length=1)
    language: Optional[str] = None
    session_id: Optional[str] = None

class FixRequest(BaseModel):
    finding_id: str

def guess_language(code: str) -> str:
    """Guess if the code is Java or Python based on simple heuristics.
    Raises HTTPException(400) if both Java and Python markers are detected (mixed code).
    """
    java_indicators = ['public class ', 'import java.', 'System.out.print', 'public static void main', 'package ', 'import javax.']
    python_indicators = ['def ', 'import os', 'import sys', 'print(', 'from ', 'elif ', 'except ', '#!/usr/bin/env python', '#!/usr/bin/python']
    has_java = any(ind in code for ind in java_indicators)
    has_python = any(ind in code for ind in python_indicators)
    if has_java and has_python:
        raise HTTPException(
            status_code=400,
            detail="Mixed code detected: the submission contains both Java and Python markers. Please submit only one language at a time."
        )
    if has_java:
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
                validation_status=f.get("validation_status"),
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
        "risk_percentage": final_state.get("risk_percentage"),
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
        "risk_percentage": orchestrator_res["risk_percentage"],
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
        "risk_percentage": orchestrator_res["risk_percentage"],
        "findings": orchestrator_res["findings"]
    }


@router.get("/history")
def get_history(
    session_id: str,
    limit: int = 50,
    db: Session = Depends(get_db)
):
    """Return the last `limit` scans for a given browser session, newest first with finding metrics."""
    from models import Finding
    scans = (
        db.query(Scan)
        .filter(Scan.session_id == session_id)
        .order_by(Scan.created_at.desc())
        .limit(limit)
        .all()
    )
    results = []
    for s in scans:
        findings = db.query(Finding).filter(Finding.scan_id == s.scan_id).all()
        findings_count = len(findings)
        critical_count = sum(1 for f in findings if (f.severity or "").lower() == "critical")
        high_count = sum(1 for f in findings if (f.severity or "").lower() == "high")
        medium_count = sum(1 for f in findings if (f.severity or "").lower() == "medium")
        low_count = sum(1 for f in findings if (f.severity or "").lower() == "low")
        sec_count = sum(1 for f in findings if (f.agent_source or "") == "security_vulnerability" or (f.category or "") == "security")
        qual_count = sum(1 for f in findings if (f.agent_source or "") == "code_analysis" or (f.category or "") == "code_quality")
        
        results.append({
            "scan_id": str(s.scan_id),
            "language": s.language.value if s.language else None,
            "source_type": s.source_type.value if s.source_type else None,
            "status": s.status.value if s.status else None,
            "created_at": s.created_at.isoformat() if s.created_at else None,
            "snippet": (s.raw_code_ref or "")[:300],
            "raw_code": s.raw_code_ref,
            "code_lines": len((s.raw_code_ref or "").splitlines()),
            "risk_score": s.risk_score,
            "risk_percentage": 100 - s.risk_score if s.risk_score is not None else 0,
            "findings_count": findings_count,
            "critical_count": critical_count,
            "high_count": high_count,
            "medium_count": medium_count,
            "low_count": low_count,
            "security_count": sec_count,
            "quality_count": qual_count,
            "summary_text": s.summary_text
        })
    return results


@router.get("/scan/{scan_id}")
@router.get("/{scan_id}")
def get_scan_details(scan_id: str, db: Session = Depends(get_db)):
    """Return full scan data including raw code, all findings, executive summary, and fixes."""
    from models import Finding
    scan_uuid = uuid.UUID(scan_id)
    scan = db.query(Scan).filter(Scan.scan_id == scan_uuid).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
        
    findings = db.query(Finding).filter(Finding.scan_id == scan_uuid).all()
    findings_list = []
    for f in findings:
        detected_by_val = ["Static Analysis"]
        if f.detected_by:
            try:
                if f.detected_by.startswith("["):
                    detected_by_val = json.loads(f.detected_by)
                else:
                    detected_by_val = [f.detected_by]
            except Exception:
                detected_by_val = [f.detected_by]

        findings_list.append({
            "finding_id": str(f.finding_id),
            "agent_source": f.agent_source or "security_vulnerability",
            "line": f.line,
            "column_num": f.column_num,
            "tool": f.tool,
            "rule_id": f.rule_id,
            "severity": f.severity or "low",
            "cvss_score": f.cvss_score,
            "category": f.category or "security",
            "owasp_type": f.owasp_type,
            "title": f.title or "Issue Detected",
            "explanation": f.explanation or "",
            "suggested_fix": f.suggested_fix or "",
            "cwe_id": f.cwe_id,
            "grounding_source": f.grounding_source,
            "confidence_score": f.confidence_score,
            "detected_by": detected_by_val,
            "original_code": f.original_code,
            "validation_status": f.validation_status or "YES",
            "status": f.status or "OPEN"
        })

    return {
        "scan_id": str(scan.scan_id),
        "session_id": scan.session_id,
        "language": scan.language.value if scan.language else None,
        "source_type": scan.source_type.value if scan.source_type else None,
        "status": scan.status.value if scan.status else None,
        "raw_code": scan.raw_code_ref,
        "code": scan.raw_code_ref,
        "validation_error": scan.validation_error,
        "summary_text": scan.summary_text,
        "risk_score": scan.risk_score,
        "risk_percentage": 100 - scan.risk_score if scan.risk_score is not None else 0,
        "created_at": scan.created_at.isoformat() if scan.created_at else None,
        "findings": findings_list,
        "syntax_errors": []
    }


@router.delete("/{scan_id}")
def delete_scan(scan_id: str, db: Session = Depends(get_db)):
    """Delete a scan and all its associated findings, chat sessions, and messages."""
    from models import Finding, ChatSession, ChatMessage, TokenUsage, Fix, FixHistory
    scan_uuid = uuid.UUID(scan_id)
    scan = db.query(Scan).filter(Scan.scan_id == scan_uuid).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    # Delete child records first (order matters for FK constraints)
    findings = db.query(Finding).filter(Finding.scan_id == scan_uuid).all()
    for f in findings:
        db.query(FixHistory).filter(FixHistory.fix_id.in_(
            db.query(Fix.fix_id).filter(Fix.finding_id == f.finding_id)
        )).delete(synchronize_session=False)
        db.query(Fix).filter(Fix.finding_id == f.finding_id).delete(synchronize_session=False)
    db.query(Finding).filter(Finding.scan_id == scan_uuid).delete(synchronize_session=False)
    chat_sessions = db.query(ChatSession).filter(ChatSession.scan_id == scan_uuid).all()
    for cs in chat_sessions:
        db.query(ChatMessage).filter(ChatMessage.session_id == cs.session_id).delete(synchronize_session=False)
    db.query(ChatSession).filter(ChatSession.scan_id == scan_uuid).delete(synchronize_session=False)
    db.query(TokenUsage).filter(TokenUsage.scan_id == scan_uuid).delete(synchronize_session=False)
    db.delete(scan)
    db.commit()
    return {"status": "deleted", "scan_id": scan_id}



@router.post("/{scan_id}/fix")
def apply_fix(scan_id: str, req: FixRequest, db: Session = Depends(get_db)):
    scan_uuid = uuid.UUID(scan_id)
    scan = db.query(Scan).filter(Scan.scan_id == scan_uuid).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
        
    from models import Finding
    finding_uuid = uuid.UUID(req.finding_id)
    finding = db.query(Finding).filter(Finding.finding_id == finding_uuid, Finding.scan_id == scan_uuid).first()
    if not finding or not finding.suggested_fix:
        raise HTTPException(status_code=404, detail="Finding or suggested fix not found")
        
    llm = ChatGroq(model="llama-3.3-70b-versatile", temperature=0)
    prompt = f"""You are an automated code patcher.
Your task is to take the ORIGINAL SOURCE CODE and apply the provided fix to it.
You MUST output the new, fully patched source code. Do NOT just return the original code.
Make sure to replace the vulnerable snippet with the suggested fix.

=== ORIGINAL SOURCE CODE ===
{scan.raw_code_ref}

=== FIX TO APPLY ===
VULNERABLE SNIPPET:
{finding.original_code or f'Line {finding.line}'}

SUGGESTED FIX:
{finding.suggested_fix}

=== INSTRUCTIONS ===
1. Apply the fix to the ORIGINAL SOURCE CODE.
2. Return ONLY the raw patched code. Do not include markdown formatting like ```python. Do not include any explanations.
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
        
        # Strip markdown blocks robustly
        import re
        patched_code = re.sub(r"^```[a-zA-Z]*\n", "", patched_code)
        patched_code = re.sub(r"\n```$", "", patched_code)
        patched_code = patched_code.strip()
        
        return {"patched_code": patched_code}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/{scan_id}/fix-all")
def apply_fix_all(scan_id: str, db: Session = Depends(get_db)):
    scan_uuid = uuid.UUID(scan_id)
    scan = db.query(Scan).filter(Scan.scan_id == scan_uuid).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
        
    from models import Finding
    findings = db.query(Finding).filter(Finding.scan_id == scan_uuid, Finding.validation_status != "NO").all()
    valid_fixes = [f for f in findings if f.suggested_fix]
    
    if not valid_fixes:
        return {"patched_code": scan.raw_code_ref}
        
    llm = ChatGroq(model="llama-3.3-70b-versatile", temperature=0)
    
    fixes_text = ""
    for f in valid_fixes:
        fixes_text += f"--- FINDING ---\n"
        fixes_text += f"ORIGINAL (OR AROUND LINE {f.line}):\n{f.original_code or ''}\n"
        fixes_text += f"SUGGESTED FIX (REPLACE WITH THIS):\n{f.suggested_fix}\n\n"
        
    prompt = f"""You are an automated code patcher.
Your task is to take the ORIGINAL SOURCE CODE and apply ALL of the following fixes to it simultaneously.
You MUST output the new, fully patched source code. Do NOT just return the original code.

=== ORIGINAL SOURCE CODE ===
{scan.raw_code_ref}

=== FIXES TO APPLY ===
{fixes_text}

=== INSTRUCTIONS ===
1. Apply ALL of the fixes to the ORIGINAL SOURCE CODE.
2. Return ONLY the raw patched code. Do not include markdown formatting like ```python. Do not include any explanations.
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
        
        # Strip markdown blocks robustly
        import re
        patched_code = re.sub(r"^```[a-zA-Z]*\n", "", patched_code)
        patched_code = re.sub(r"\n```$", "", patched_code)
        patched_code = patched_code.strip()
        
        return {"patched_code": patched_code}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
