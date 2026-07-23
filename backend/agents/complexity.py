from typing import Dict, Any
from .state import ScanState

def complexity_node(state: ScanState) -> Dict[str, Any]:
    """
    Complexity Node - Analyzes code complexity (e.g. cyclomatic complexity).
    Mocked for this phase.
    """
    code = state["code"]
    findings = []
    
    # Mock finding for overly complex functions
    if code.count("if") > 3 or code.count("for") > 2:
        findings.append({
            "agent_source": "complexity",
            "title": "High Cyclomatic Complexity",
            "tool": "complexity_scanner",
            "rule_id": "COMP-001",
            "severity": "medium",
            "category": "maintainability",
            "explanation": "This function has a high number of branches, making it harder to maintain and test.",
            "suggested_fix": "Consider refactoring into smaller, single-purpose functions.",
            "line": 1
        })
        
    print(f"[Complexity Node] generated {len(findings)} findings")
    return {"complexity_findings": findings}
