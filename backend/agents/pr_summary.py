import json
from typing import Dict, Any
from .state import ScanState
from langchain_anthropic import ChatAnthropic
from langchain_core.messages import HumanMessage, SystemMessage

def pr_summary_node(state: ScanState) -> Dict[str, Any]:
    code = state["code"]
    findings = state.get("findings", [])
    
    if not findings:
        return {"summary_text": "No issues found. The code looks solid!"}
        
    llm = ChatAnthropic(model="claude-3-5-sonnet-20241022", temperature=0)
    
    prompt = f"""You are a Senior Staff Engineer writing a PR review summary.
Based on the following findings, write a cohesive, prioritizing, human-readable summary of the code review. 
Highlight the most critical issues first.
Be concise but comprehensive. Use markdown for formatting.

FINDINGS:
{json.dumps(findings, indent=2)}
"""

    try:
        response = llm.invoke([
            SystemMessage(content="You are a senior reviewer writing a PR summary."),
            HumanMessage(content=prompt)
        ])
        return {"summary_text": response.content.strip()}
    except Exception as e:
        print(f"PR Summary Agent LLM error: {e}")
        return {"summary_text": "Failed to generate summary."}
