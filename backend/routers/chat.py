from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from database import get_db
from models import Scan, ChatSession, ChatMessage, Finding
from pydantic import BaseModel
from typing import Optional, List
from langchain_anthropic import ChatAnthropic
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
        {"title": f.title, "explanation": f.explanation, "line": f.line, "severity": f.severity} 
        for f in findings
    ]
    
    rag_chunks = retrieve(db, req.message, k=3)
    context_text = "\n\n".join([f"[{c.source_name}]: {c.chunk_text}" for c in rag_chunks])
    
    llm = ChatAnthropic(model="claude-3-5-sonnet-20241022", temperature=0.7)
    
    system_prompt = f"""You are an expert Security & Code Quality Assistant. 
You are discussing a code scan with the user.

SCAN FINDINGS:
{json.dumps(findings_data, indent=2)}

SECURITY KNOWLEDGE BASE CONTEXT:
{context_text}

Answer the user's questions about the code and findings. Cite the KB context and findings where relevant.
"""
    messages = [SystemMessage(content=system_prompt)]
    for msg in past_messages:
        if msg.role == "user":
            messages.append(HumanMessage(content=msg.content))
        else:
            messages.append(AIMessage(content=msg.content))
            
    try:
        response = llm.invoke(messages)
        ai_text = response.content
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
