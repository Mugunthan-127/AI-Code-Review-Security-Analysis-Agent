import json
from typing import Dict, Any
from .state import ScanState
from langchain_groq import ChatGroq
from langchain_core.messages import HumanMessage, SystemMessage
from pydantic import BaseModel, Field
from typing import List, Dict, Optional

class PrioritizedFinding(BaseModel):
    title: str = Field(description="The title of the finding")
    severity: str = Field(description="The severity of the finding")
    recommendation: str = Field(description="A short recommendation for fixing")
    fix_time_estimate: str = Field(description="Estimated time to fix, e.g. '15 min', '1 hour', '2 hours'")

class PRSummary(BaseModel):
    executive_overview: str = Field(description="2-3 sentence plain-language summary of overall code health and the most important thing to fix first.")
    severity_breakdown: Dict[str, int] = Field(description="Counts of findings by severity (e.g. {'critical': 1, 'high': 0, 'medium': 2, 'low': 0})")
    prioritized_findings: List[PrioritizedFinding] = Field(description="List of the top 3-5 most important distinct issues to fix, ordered by severity.")
    total_estimated_fix_time: str = Field(description="Total estimated time to fix all prioritized issues, e.g. '3-5 hours'")

def pr_summary_node(state: ScanState) -> Dict[str, Any]:
    code = state["code"]
    findings = state.get("findings", [])
    
    valid_findings = [f for f in findings if f.get("validation_status") != "NO"]
    
    if not valid_findings:
        empty_summary = {
            "executive_overview": "No security vulnerabilities or code quality issues were detected. The application follows secure coding practices.",
            "severity_breakdown": {"critical": 0, "high": 0, "medium": 0, "low": 0},
            "prioritized_findings": [],
            "total_estimated_fix_time": "0 min"
        }
        return {"summary_text": json.dumps(empty_summary)}
        
    llm = ChatGroq(model="llama-3.3-70b-versatile", temperature=0)
    structured_llm = llm.with_structured_output(PRSummary)

    prompt = f"""You are a Senior Staff Engineer writing a PR review summary.
Based on the following findings, generate a structured executive summary.

FINDINGS:
{json.dumps(valid_findings, indent=2)}

Guidelines:
1. 'executive_overview' should be a 2-3 sentence plain-language summary of overall code health and the most critical thing to fix first.
2. 'severity_breakdown' must accurately count the severities of the provided findings.
3. 'prioritized_findings' should list the top 3-5 most important distinct issues to fix, ordered by severity. Each MUST include a realistic 'fix_time_estimate' (e.g. '15 min', '30 min', '1 hour', '2 hours').
4. 'total_estimated_fix_time' should be the total estimated time to fix all prioritized issues.
"""

    try:
        response = structured_llm.invoke([
            SystemMessage(content="You are a senior reviewer writing a PR summary."),
            HumanMessage(content=prompt)
        ])
        return {"summary_text": json.dumps(response.model_dump(), indent=2)}
    except Exception as e:
        print(f"PR Summary Agent LLM error: {e}")
        fallback_summary = {
            "executive_overview": "Analysis Complete. Could not generate detailed AI summary.",
            "severity_breakdown": {"critical": 0, "high": 0, "medium": 0, "low": 0},
            "prioritized_findings": [],
            "total_estimated_fix_time": "N/A"
        }
        return {"summary_text": json.dumps(fallback_summary)}
