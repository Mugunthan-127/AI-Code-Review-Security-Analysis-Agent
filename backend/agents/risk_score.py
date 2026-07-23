from typing import Dict, Any
from .state import ScanState

def risk_score_node(state: ScanState) -> Dict[str, Any]:
    """
    Risk Score Node - Calculates an overall risk score from 0-100 based on merged findings.
    0 = Perfect (No risk), 100 = Maximum Risk.
    """
    findings = state.get("findings", [])
    
    score = 0
    for f in findings:
        sev = str(f.get("severity", "low")).lower()
        if sev == "critical":
            score += 30
        elif sev == "high":
            score += 15
        elif sev == "medium":
            score += 5
        elif sev == "low":
            score += 1
            
    # Cap at 100
    final_score = min(100, score)
    
    print(f"[Risk Score Node] Calculated score: {final_score}/100")
    return {"risk_score": final_score}
