"""
Multi-Agent Orchestrator — Milestone 2
Implements Milestone 2's parallel execution requirement:
  - Code Analysis Agent and Security Vulnerability Agent run in parallel (fan-out)
  - A Merge Node deduplicates and sorts their outputs into a unified findings list (fan-in)
  - Remediation Agent and PR Summary Agent run sequentially after merging

Architecture:
                    START
                      │
          ┌───────────┴───────────┐
          ▼                       ▼
  code_analysis_node     security_vuln_node
     (Pylint/PMD)          (Bandit/SpotBugs)
          │                       │
          └───────────┬───────────┘
                      ▼
                 merge_node
            (deduplicate + sort)
                      │
               remediation_node
             (LLM suggested fixes)
                      │
               pr_summary_node
            (PR summary narrative)
                      │
                     END
"""
from typing import Dict, Any, List
from langgraph.graph import StateGraph, START, END
from .state import ScanState
from .validation import validation_node
from .code_analysis import code_analysis_node
from .security_vuln import security_vuln_node
from .complexity import complexity_node
from .dependency import dependency_node
from .remediation import remediation_node
from .pr_summary import pr_summary_node
from .risk_score import risk_score_node


# ---------------------------------------------------------------------------
# Severity ordering for sort (lower number = higher priority)
# ---------------------------------------------------------------------------
SEVERITY_ORDER = {
    "critical": 0,
    "high":     1,
    "medium":   2,
    "low":      3,
    "info":     4,
}


def _severity_rank(finding: Dict[str, Any]) -> int:
    """Return numeric rank for a finding's severity (lower = more severe)."""
    sev = str(finding.get("severity", "low")).lower()
    return SEVERITY_ORDER.get(sev, 5)


def merge_node(state: ScanState) -> Dict[str, Any]:
    """
    Merge Node — combines outputs from all 5 parallel analysis agents.
    """
    code_findings = state.get("code_analysis_findings", []) or []
    sec_findings  = state.get("security_findings", []) or []
    comp_findings = state.get("complexity_findings", []) or []
    dep_findings  = state.get("dependency_findings", []) or []

    all_findings: List[Dict[str, Any]] = code_findings + sec_findings + comp_findings + dep_findings

    # Deduplication
    seen: List[Dict[str, Any]] = []
    for f in all_findings:
        duplicate_found = False
        for existing in seen:
            same_line = existing.get("line") == f.get("line")
            same_owasp = existing.get("owasp_type") and existing.get("owasp_type") == f.get("owasp_type")
            same_rule = existing.get("rule_id") and existing.get("rule_id") == f.get("rule_id")
            
            if same_line and (same_owasp or same_rule):
                duplicate_found = True
                
                # Merge logic
                existing_rank = _severity_rank(existing)
                incoming_rank = _severity_rank(f)
                
                # Keep highest severity
                if incoming_rank < existing_rank:
                    existing["severity"] = f.get("severity")
                    existing["title"] = f.get("title") or existing.get("title")
                    existing["explanation"] = f.get("explanation") or existing.get("explanation")
                    existing["agent_source"] = f.get("agent_source") or existing.get("agent_source")
                    
                # Merge detected_by
                existing_detected = existing.get("detected_by", [])
                if isinstance(existing_detected, str):
                    existing_detected = [existing_detected]
                incoming_detected = f.get("detected_by", [])
                if isinstance(incoming_detected, str):
                    incoming_detected = [incoming_detected]
                
                if not incoming_detected and f.get("tool"):
                    incoming_detected = [f.get("tool").capitalize()]
                
                merged_detected = list(set(existing_detected + incoming_detected))
                existing["detected_by"] = merged_detected
                
                break
                
        if not duplicate_found:
            # Ensure detected_by is a list
            if not f.get("detected_by") and f.get("tool"):
                f["detected_by"] = [f.get("tool").capitalize()]
            elif isinstance(f.get("detected_by"), str):
                f["detected_by"] = [f.get("detected_by")]
            seen.append(f)

    merged = seen
    merged.sort(key=lambda f: (_severity_rank(f), f.get("line") or 0))

    print(f"[Merge Node] Deduplicated to {len(merged)} total findings")
    return {"findings": merged}


def validation_router(state: ScanState):
    """Route based on whether the code passed syntax validation."""
    if state.get("is_valid", False):
        return ["code_analysis", "security_vuln", "complexity", "dependency"]
    # If invalid, short-circuit the graph and exit immediately.
    return END

# ---------------------------------------------------------------------------
# Build the LangGraph workflow
# ---------------------------------------------------------------------------

workflow = StateGraph(ScanState)

# Register all nodes
workflow.add_node("validation",     validation_node)
workflow.add_node("code_analysis",  code_analysis_node)
workflow.add_node("security_vuln",  security_vuln_node)
workflow.add_node("complexity",     complexity_node)
workflow.add_node("dependency",     dependency_node)
workflow.add_node("merge",          merge_node)
workflow.add_node("risk_score",     risk_score_node)
workflow.add_node("remediation",    remediation_node)
workflow.add_node("pr_summary",     pr_summary_node)

# Start with validation
workflow.add_edge(START, "validation")

# Fan-out: conditionally launch 5 agents if valid
workflow.add_conditional_edges("validation", validation_router)

# Fan-in: all agents → merge node
workflow.add_edge("code_analysis", "merge")
workflow.add_edge("security_vuln", "merge")
workflow.add_edge("complexity", "merge")
workflow.add_edge("dependency", "merge")

# Sequential post-merge pipeline
workflow.add_edge("merge",       "risk_score")
workflow.add_edge("risk_score",  "remediation")
workflow.add_edge("remediation", "pr_summary")
workflow.add_edge("pr_summary",  END)

app = workflow.compile()

