from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from database import get_db
from models import Scan, ChatSession, ChatMessage, Finding
from pydantic import BaseModel
from typing import Optional, List
from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_core.messages import HumanMessage, SystemMessage, AIMessage
from services.rag import retrieve
import json

router = APIRouter()

class ChatRequest(BaseModel):
    message: str
    session_id: Optional[str] = None

@router.post("/{scan_id}/chat")
def chat_with_scan(scan_id: str, req: ChatRequest, db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.scan_id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
        
    if req.session_id:
        chat_session = db.query(ChatSession).filter(ChatSession.session_id == req.session_id).first()
        if not chat_session:
            raise HTTPException(status_code=404, detail="Chat session not found")
    else:
        chat_session = ChatSession(scan_id=scan.scan_id)
        db.add(chat_session)
        db.commit()
        db.refresh(chat_session)
        
    user_msg = ChatMessage(session_id=chat_session.session_id, role="user", content=req.message)
    db.add(user_msg)
    
    past_messages = db.query(ChatMessage).filter(ChatMessage.session_id == chat_session.session_id).order_by(ChatMessage.created_at).all()
    
    findings = db.query(Finding).filter(Finding.scan_id == scan_id).all()
    findings_data = [
        {"title": f.title, "explanation": f.explanation, "suggested_fix": f.suggested_fix, "line": f.line, "severity": f.severity, "rule_id": f.rule_id, "tool": f.tool} 
        for f in findings
    ]
    
    rag_chunks = retrieve(db, req.message, k=3)
    context_text = "\n\n".join([f"[{c.source_name}]: {c.chunk_text}" for c in rag_chunks])
    
    llm = ChatGoogleGenerativeAI(model="gemini-flash-latest", temperature=0.7)
    
    system_prompt = f"""You are an expert Security & Code Quality Intelligent Tutor.
Your goal is to help the user understand the vulnerabilities and code quality issues in their code, not just fix it for them blindly.

ORIGINAL CODE:
```
{scan.raw_code_ref}
```

SCAN FINDINGS:
{json.dumps(findings_data, indent=2)}

SECURITY KNOWLEDGE BASE CONTEXT:
{context_text}

Guidelines:
1. "Explain Like Beginner": Use analogies, avoid extreme jargon, and break down concepts simply.
2. "Generate Secure Version": Provide the fully fixed code block.
3. "Compare Old vs New": Show the vulnerable lines alongside the fixed lines using diff blocks.
4. "Why Tool found this?": Explain the underlying rule or heuristic that triggered the finding.
5. "Which OWASP?": Map the finding to the specific OWASP Top 10 category and explain why.
6. "Show Example": Provide a standalone, simplified code example demonstrating the vulnerability and the fix.
7. Always format code using markdown. Use clear headings and bullet points for readability.
"""
    messages = [SystemMessage(content=system_prompt)]
    for msg in past_messages:
        content_str = msg.content if msg.content and str(msg.content).strip() else " "
        if msg.role == "user":
            messages.append(HumanMessage(content=content_str))
        else:
            messages.append(AIMessage(content=content_str))
            
    try:
        response = llm.invoke(messages)
        raw_content = response.content
        if isinstance(raw_content, list):
            raw_content = raw_content[0].get("text", "") if isinstance(raw_content[0], dict) else str(raw_content[0])
        ai_text = str(raw_content)
    except Exception as e:
        print(f"Chat LLM error: {e}")
        ai_text = "I'm sorry, I encountered an error while processing your request."
        
    ai_msg = ChatMessage(session_id=chat_session.session_id, role="assistant", content=ai_text)
    db.add(ai_msg)
    db.commit()
    
    return {
        "session_id": str(chat_session.session_id),
        "reply": ai_text
    }
