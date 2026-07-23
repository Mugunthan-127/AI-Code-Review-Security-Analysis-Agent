import json
from typing import Dict, Any
from .state import ScanState
from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_core.messages import HumanMessage, SystemMessage

def pr_summary_node(state: ScanState) -> Dict[str, Any]:
    code = state["code"]
    findings = state.get("findings", [])
    
    if not findings:
        return {"summary_text": "No issues found. The code looks solid!"}
        
    llm = ChatGoogleGenerativeAI(model="gemini-flash-latest", temperature=0)
    
    prompt = f"""You are a Senior Staff Engineer writing a PR review summary.
Based on the following findings, write a highly structured, Copilot-style summary.
Format your response exactly using these Markdown headers and nothing else. Do not add conversational filler.

### Overall Risk
[State Critical, High, Medium, or Low based on the highest severity finding]

### Breakdown
- **Security:** [X] Issues
- **Quality:** [X] Issues
- **Complexity:** [X] Issues
- **Dependency:** [X] Issues
- **License:** [X] Issues

### Estimated Fix Time
[Provide a realistic time estimate, e.g., '20 minutes', '2 hours', based on the complexity and number of findings]

### Priority
[List the top 3-5 most important issues to fix, numbered 1, 2, 3...]

### Recommendation
[Provide a 1-2 sentence high-level recommendation, e.g., 'Fix SQL Injection immediately before merging.']

FINDINGS:
{json.dumps(findings, indent=2)}
"""

    try:
        response = llm.invoke([
            SystemMessage(content="You are a senior reviewer writing a PR summary."),
            HumanMessage(content=prompt)
        ])
        raw_content = response.content
        if isinstance(raw_content, list):
            raw_content = raw_content[0].get("text", "") if isinstance(raw_content[0], dict) else str(raw_content[0])
        return {"summary_text": str(raw_content).strip()}
    except Exception as e:
        print(f"PR Summary Agent LLM error: {e}")
        return {"summary_text": "Failed to generate summary."}
