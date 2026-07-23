from typing import Dict, Any
from .state import ScanState

def license_node(state: ScanState) -> Dict[str, Any]:
    """
    License Node - Analyzes code for missing or incompatible open-source licenses.
    Mocked for this phase.
    """
    code = state["code"]
    findings = []
    
    # Mock finding: if no license header
    if "Copyright" not in code and "License" not in code:
        findings.append({
            "agent_source": "license",
            "title": "Missing License Header",
            "tool": "license_scanner",
            "rule_id": "LIC-001",
            "severity": "info",
            "category": "compliance",
            "explanation": "No open-source license or copyright header was detected in this file.",
            "suggested_fix": "# Copyright (c) [Year] [Owner]\n# Licensed under the MIT License.",
            "line": 1
        })
        
    print(f"[License Node] generated {len(findings)} findings")
    return {"license_findings": findings}
