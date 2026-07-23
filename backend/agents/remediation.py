"""
Remediation Agent — generates suggested code fixes for each finding.
Runs after the merge node, operating on the unified findings list.
"""
import json
from typing import Dict, Any
from .state import ScanState
from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_core.messages import HumanMessage, SystemMessage


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

    llm = ChatGoogleGenerativeAI(model="gemini-flash-latest", temperature=0)

    prompt = f"""You are a senior Code Remediation Expert. 
I will provide source code and a list of findings (security vulnerabilities and code quality issues).

SOURCE CODE:
{code}

FINDINGS:
{json.dumps(findings, indent=2)}

For EACH finding:
1. Extract the 'original_code', which is the exact vulnerable snippet from the SOURCE CODE.
2. Add a 'suggested_fix' field containing a concrete, minimal code snippet that resolves the issue.
   - Use the same language as the source code.
   - The fix should be focused on the specific line/issue, not a complete file rewrite.
   - Prefer idiomatic, production-quality code.
3. If a finding already has a 'suggested_fix', improve it if possible.
4. Do NOT change any other fields ('line', 'severity', 'agent_source', 'owasp_type', etc.).
5. Return the SAME number of findings as input.

Return ONLY a JSON array of the updated findings. No markdown, no preamble."""

    try:
        response = llm.invoke([
            SystemMessage(content="You return ONLY a valid JSON array. No markdown, no extra text."),
            HumanMessage(content=prompt)
        ])
        raw_content = response.content
        if isinstance(raw_content, list):
            raw_content = raw_content[0].get("text", "") if isinstance(raw_content[0], dict) else str(raw_content[0])
        content = str(raw_content).strip()
        if content.startswith("```json"):
            content = content[7:]
        if content.startswith("```"):
            content = content[3:]
        if content.endswith("```"):
            content = content[:-3]
        enriched = json.loads(content.strip())
        return {"findings": enriched}
    except Exception as e:
        print(f"[Remediation Agent] LLM error: {e}")
        return {"findings": findings}
