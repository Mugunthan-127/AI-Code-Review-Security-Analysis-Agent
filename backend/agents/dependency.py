from typing import Dict, Any
from .state import ScanState

def dependency_node(state: ScanState) -> Dict[str, Any]:
    """
    Dependency Node - Analyzes code for outdated or vulnerable dependencies.
    Mocked for this phase.
    """
    code = state["code"]
    findings = []
    
    # Mock finding for hardcoded vulnerable dependencies via imports
    if "import requests" in code or "from requests" in code:
        findings.append({
            "agent_source": "dependency",
            "title": "Potentially Vulnerable Dependency (requests)",
            "tool": "dependency_scanner",
            "rule_id": "DEP-001",
            "severity": "low",
            "category": "supply_chain",
            "explanation": "The 'requests' library was detected. Ensure you are using the latest version to avoid known vulnerabilities like CVE-2023-32289.",
            "suggested_fix": "Pin the dependency in requirements.txt (e.g., requests>=2.31.0).",
            "line": 1
        })
        
    print(f"[Dependency Node] generated {len(findings)} findings")
    return {"dependency_findings": findings}
