from typing import Dict, Any
from .state import ScanState

def risk_score_node(state: ScanState) -> Dict[str, Any]:
    """
    Risk Score Node - Calculates an overall code health score from 0-100 based on merged findings.
    100 = Perfect (No risk), 0 = Maximum Risk.
    Also computes risk_percentage: 0% = no risk, 100% = maximum risk.
    """
    findings = state.get("findings", [])
    
    penalty = 0
    for f in findings:
        if f.get("validation_status") == "NO":
            continue
            
        sev = str(f.get("severity", "low")).lower()
        if sev == "critical":
            penalty += 15
        elif sev == "high":
            penalty += 8
        elif sev == "medium":
            penalty += 3
        elif sev == "low":
            penalty += 1
            
    # Health score starts at 100, floor at 0
    final_score = max(0, 100 - penalty)
    # Risk percentage is the inverse: 0% = safe, 100% = critical
    risk_percentage = min(100, penalty)
    
    print(f"[Risk Score Node] Health={final_score}/100, Risk={risk_percentage}%")
    return {"risk_score": final_score, "risk_percentage": risk_percentage}
