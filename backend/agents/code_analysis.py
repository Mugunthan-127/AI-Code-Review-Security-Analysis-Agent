"""
Code Analysis Agent — Milestone 2
Detects code smells, complexity issues, design anti-patterns, and poor coding practices.
Severity is deterministically assigned based on a defined rubric — no LLM required for classification.
An LLM enrichment pass improves title/explanation quality using the raw tool output.
"""
from typing import Dict, Any, List
from .state import ScanState
from services.python_analyzer import run_pylint, run_ruff, run_semgrep as run_python_semgrep
from services.java_analyzer import run_pmd, run_checkstyle, run_semgrep as run_java_semgrep
from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_core.messages import HumanMessage, SystemMessage
import json


# ---------------------------------------------------------------------------
# Severity Rubric — Milestone 2 spec: define a clear rubric
# ---------------------------------------------------------------------------
# HIGH  — Design anti-patterns likely to cause bugs (god classes, deeply
#         nested conditionals, mutable defaults, etc.)
# MEDIUM — Significant complexity or maintainability issues (high cyclomatic
#         complexity, very long methods/functions)
# LOW   — Style/best-practice deviations with low functional risk (naming
#         conventions, missing docstrings, whitespace)
# ---------------------------------------------------------------------------

# Pylint rule_id → forced severity override (takes precedence over type_map)
PYLINT_SEVERITY_OVERRIDES: Dict[str, str] = {
    # High — design anti-patterns / likely-to-cause-bugs
    "W0102": "high",   # dangerous-default-value (mutable default argument)
    "W0106": "high",   # expression-not-assigned
    "W0201": "high",   # attribute-defined-outside-init
    "W0212": "high",   # protected-access
    "W0611": "high",   # unused-import (often masks deeper problems)
    "E1101": "high",   # module-has-no-member
    "E0611": "high",   # no-name-in-module
    "W0703": "high",   # broad-except (swallows all exceptions)
    "W0702": "high",   # bare-except
    "R0201": "high",   # no-self-use (design smell in class)
    # Medium — complexity / maintainability
    "R0912": "medium", # too-many-branches (cyclomatic complexity)
    "R0914": "medium", # too-many-locals
    "R0915": "medium", # too-many-statements
    "R0913": "medium", # too-many-arguments
    "R0902": "medium", # too-many-instance-attributes (god class indicator)
    "C0301": "low",    # line-too-long
    "C0302": "medium", # too-many-lines
    "R0801": "medium", # duplicate-code
    # Low — naming / docstring conventions
    "C0103": "low",    # invalid-name
    "C0115": "low",    # missing-class-docstring
    "C0116": "low",    # missing-function-docstring
    "C0114": "low",    # missing-module-docstring
    "W0611": "medium", # unused-import
}

# Pylint message type → default severity (fallback if no specific override)
PYLINT_TYPE_MAP: Dict[str, str] = {
    "fatal":      "critical",
    "error":      "high",
    "warning":    "medium",
    "convention": "low",
    "refactor":   "medium",
    "information":"low",
}

# PMD priority → severity
PMD_PRIORITY_MAP: Dict[str, str] = {
    "1": "high",    # Critical design anti-pattern
    "2": "high",    # Major issue
    "3": "medium",  # Significant complexity/maintainability issue
    "4": "low",     # Minor style deviation
    "5": "low",     # Very minor
}


def _map_pylint_severity(rule_id: str, msg_type: str) -> str:
    """Apply severity rubric to a Pylint finding."""
    if rule_id and rule_id in PYLINT_SEVERITY_OVERRIDES:
        return PYLINT_SEVERITY_OVERRIDES[rule_id]
    return PYLINT_TYPE_MAP.get(msg_type, "low")


def _map_pmd_severity(priority: str) -> str:
    """Apply severity rubric to a PMD finding."""
    return PMD_PRIORITY_MAP.get(str(priority), "low")


def _run_python_quality_tools(code: str) -> List[Dict[str, Any]]:
    """Run Python quality tools (Pylint, Ruff, Semgrep) and apply severity rubric."""
    raw_pylint = run_pylint(code)
    raw_ruff = run_ruff(code)
    raw_semgrep = run_python_semgrep(code, config="p/default")
    
    enriched = []
    # Pylint
    for item in raw_pylint:
        rule_id = item.get("rule_id", "")
        rubric_severity = _map_pylint_severity(
            rule_id, 
            {v: k for k, v in PYLINT_TYPE_MAP.items()}.get(item.get("severity", "low"), "convention")
        )
        enriched.append({
            **item,
            "agent_source": "code_analysis",
            "severity": rubric_severity,
            "category": "code_quality",
        })
    # Ruff
    for item in raw_ruff:
        enriched.append({
            **item,
            "agent_source": "code_analysis",
            "category": "code_quality",
        })
    # Semgrep (filter for code_quality)
    for item in raw_semgrep:
        if item.get("category") == "code_quality":
            enriched.append({
                **item,
                "agent_source": "code_analysis",
                "category": "code_quality",
            })
    return enriched


def _run_java_quality_tools(code: str) -> List[Dict[str, Any]]:
    """Run Java quality tools (PMD, Checkstyle, Semgrep) and apply severity rubric."""
    raw_pmd = run_pmd(code)
    raw_checkstyle = run_checkstyle(code)
    raw_semgrep = run_java_semgrep(code, config="p/default")
    
    enriched = []
    # PMD
    for item in raw_pmd:
        enriched.append({
            **item,
            "agent_source": "code_analysis",
            "category": "code_quality",
        })
    # Checkstyle
    for item in raw_checkstyle:
        enriched.append({
            **item,
            "agent_source": "code_analysis",
            "category": "code_quality",
        })
    # Semgrep (filter for code_quality)
    for item in raw_semgrep:
        if item.get("category") == "code_quality":
            enriched.append({
                **item,
                "agent_source": "code_analysis",
                "category": "code_quality",
            })
    return enriched


def code_analysis_node(state: ScanState) -> Dict[str, Any]:
    """
    Code Analysis Agent node for LangGraph.
    
    Input state keys used: code, language
    Output state keys produced: findings (appended)
    
    This node runs a static code quality tool (Pylint for Python, PMD for Java)
    and enriches each finding with a standardised severity (per the defined rubric)
    and an LLM-improved title/explanation.
    """
    code = state["code"]
    lang = state["language"]

    # Step 1 — Run the appropriate static tool with severity rubric applied
    if lang == "python":
        raw_findings = _run_python_quality_tools(code)
    else:
        raw_findings = _run_java_quality_tools(code)

    if not raw_findings:
        return {"code_analysis_findings": []}

    # Step 2 — LLM enrichment: improve title/explanation quality
    # (does NOT change severity or add new findings)
    llm = ChatGoogleGenerativeAI(model="gemini-flash-latest", temperature=0)

    prompt = f"""You are an expert Code Quality Reviewer. Below is a list of raw code analysis findings from a static analysis tool run on the following {lang} code.

CODE:
{code}

RAW FINDINGS:
{json.dumps(raw_findings, indent=2)}

Your task:
1. For each finding, improve the 'title' to be concise and descriptive (max 10 words).
2. Improve the 'explanation' to be clear, developer-friendly, and actionable (2-4 sentences).
3. Do NOT change 'line', 'column', 'tool', 'rule_id', 'severity', 'category', or 'agent_source'.
4. Do NOT invent new findings or remove existing ones.
5. Return a JSON array with the exact same number of items.

Return ONLY the JSON array. No markdown, no preamble."""

    try:
        response = llm.invoke([
            SystemMessage(content="You return ONLY a valid JSON array. No markdown wrapping, no extra text."),
            HumanMessage(content=prompt)
        ])
        raw_content = response.content
        if isinstance(raw_content, list):
            raw_content = raw_content[0].get("text", "") if isinstance(raw_content[0], dict) else str(raw_content[0])
        content = str(raw_content).strip()
        # Strip any accidental markdown fences
        if content.startswith("```json"):
            content = content[7:]
        if content.startswith("```"):
            content = content[3:]
        if content.endswith("```"):
            content = content[:-3]
        enriched_findings = json.loads(content.strip())
        # Safety: ensure agent_source is set on every returned item
        for f in enriched_findings:
            f.setdefault("agent_source", "code_analysis")
        return {"code_analysis_findings": enriched_findings}
    except Exception as e:
        print(f"[Code Analysis Agent] LLM enrichment error: {e}")
        return {"code_analysis_findings": raw_findings}
