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
from .license import license_node
from .risk_score import risk_score_node
from .remediation import remediation_node
from .pr_summary import pr_summary_node


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
    lic_findings  = state.get("license_findings", []) or []

    all_findings: List[Dict[str, Any]] = code_findings + sec_findings + comp_findings + dep_findings + lic_findings

    # Deduplication: key = (line, rule_id)
    seen: Dict[tuple, Dict[str, Any]] = {}
    for f in all_findings:
        key = (f.get("line"), f.get("rule_id", ""))
        if key not in seen:
            seen[key] = f
        else:
            existing = seen[key]
            existing_rank = _severity_rank(existing)
            incoming_rank = _severity_rank(f)
            if incoming_rank < existing_rank:
                # Incoming is more severe — replace
                seen[key] = f
            elif incoming_rank == existing_rank:
                # Equal severity — prefer security_vulnerability source
                if f.get("agent_source") == "security_vulnerability":
                    seen[key] = f

    merged = list(seen.values())
    merged.sort(key=lambda f: (_severity_rank(f), f.get("line") or 0))

    print(f"[Merge Node] Deduplicated to {len(merged)} total findings")
    return {"findings": merged}


def validation_router(state: ScanState):
    """Route based on whether the code passed syntax validation."""
    if state.get("is_valid", False):
        return ["code_analysis", "security_vuln", "complexity", "dependency", "license"]
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
workflow.add_node("license",        license_node)
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
workflow.add_edge("license", "merge")

# Sequential post-merge pipeline
workflow.add_edge("merge",       "risk_score")
workflow.add_edge("risk_score",  "remediation")
workflow.add_edge("remediation", "pr_summary")
workflow.add_edge("pr_summary",  END)

app = workflow.compile()

