"""
Remediation Agent — generates suggested code fixes for each finding.
Runs after the merge node, operating on the unified findings list.
"""
import json
from typing import Dict, Any
from .state import ScanState
from langchain_groq import ChatGroq
from langchain_core.messages import HumanMessage, SystemMessage
from pydantic import BaseModel, Field
from typing import Optional, List
from database import SessionLocal
from services.rag import retrieve

def remediation_node(state: ScanState) -> Dict[str, Any]:
    """
    Remediation Agent node for LangGraph.

    Takes the merged findings list and adds a 'suggested_fix' code snippet
    to each finding. Works on both code quality and security findings.
    """
    code = state["code"]
    findings = state.get("findings", [])

    if not findings:
        return {}
        
    db = SessionLocal()
    rag_contexts = []
    try:
        for f in findings:
            query = f.get("rule_id") or f.get("title") or "secure coding practices"
            chunks = retrieve(db, query, k=1)
            for c in chunks:
                rag_contexts.append(f"[{c.source_name}]: {c.chunk_text}")
    except Exception as e:
        print(f"[Remediation RAG Error] {e}")
    finally:
        db.close()
        
    rag_contexts = list(set(rag_contexts))
    kb_context_str = "\n\n".join(rag_contexts) if rag_contexts else "No KB context available."

    class RemediatedFinding(BaseModel):
        line: Optional[int] = Field(None, description="Line number of the finding")
        column_num: Optional[int] = Field(None, description="Column number")
        tool: Optional[str] = Field(None, description="Tool that detected it")
        rule_id: Optional[str] = Field(None, description="Rule ID")
        severity: str = Field(description="Severity (critical, high, medium, low)")
        category: str = Field(description="Category")
        agent_source: str = Field(description="Agent source")
        owasp_type: Optional[str] = Field(None, description="OWASP vulnerability type")
        cwe_id: Optional[str] = Field(None, description="CWE ID")
        detected_by: Optional[List[str]] = Field(None, description="List of tools that detected this")
        validation_status: Optional[str] = Field(None, description="YES, NO, or MAYBE")
        title: str = Field(description="Title")
        explanation: str = Field(description="Explanation")
        grounding_source: Optional[str] = Field(None, description="KB source filename if relevant")
        confidence_score: Optional[str] = Field(None, description="Confidence percentage")
        cvss_score: Optional[float] = Field(None, description="CVSS v3 score")
        original_code: Optional[str] = Field(None, description="The exact vulnerable snippet from the SOURCE CODE")
        suggested_fix: Optional[str] = Field(None, description="A complete, optimized, and efficient code block that fully resolves the issue")

    class RemediationFindingsList(BaseModel):
        findings: List[RemediatedFinding] = Field(description="List of findings with remediation added")

    llm = ChatGroq(model="llama-3.3-70b-versatile", temperature=0)
    structured_llm = llm.with_structured_output(RemediationFindingsList)

    prompt = f"""You are a senior Code Remediation Expert. 
I will provide source code and a list of findings (security vulnerabilities and code quality issues).

SOURCE CODE:
{code}

FINDINGS:
{json.dumps(findings, indent=2)}

SECURITY KNOWLEDGE BASE CONTEXT:
{kb_context_str}

For EACH finding:
1. Extract the 'original_code', which is the exact vulnerable snippet from the SOURCE CODE.
2. Add a 'suggested_fix' field containing a complete, optimized, and efficient code snippet that fully resolves the issue.
   - Use the same language as the source code.
   - Provide the complete updated function, class, or logical block instead of just a minimal line fix, ensuring it is efficient and highly optimized.
   - Prefer idiomatic, production-quality code.
3. Rewrite the 'explanation' field to provide a detailed, best-practice explanation based on the SECURITY KNOWLEDGE BASE CONTEXT provided.
4. Set the 'grounding_source' field to the exact bracketed source name (e.g., 'owasp_a01.md') from the KB context that you used to form the explanation.
5. Do NOT change any other fields ('line', 'severity', 'agent_source', 'owasp_type', etc.).
6. Return the SAME number of findings as input.
"""

    try:
        response = structured_llm.invoke([
            SystemMessage(content="You extract structured findings with remediation."),
            HumanMessage(content=prompt)
        ])
        enriched = [f.model_dump(exclude_none=True) for f in response.findings]
        return {"findings": enriched}
    except Exception as e:
        print(f"[Remediation Agent] LLM error: {e}")
        return {"findings": findings}
