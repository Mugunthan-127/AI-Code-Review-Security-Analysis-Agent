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
from .code_analysis import code_analysis_node
from .security_vuln import security_vuln_node
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
    Merge Node — combines Code Analysis and Security Vulnerability agent outputs.

    Steps:
    1. Concatenate both findings lists.
    2. Deduplicate: if two findings share the same (file/line, rule_id), keep
       the one with the higher severity. If equal severity, prefer 'security_vulnerability'.
    3. Sort: by severity (Critical/High first) then by line number ascending.
    """
    code_findings = state.get("code_analysis_findings", []) or []
    sec_findings  = state.get("security_findings", []) or []

    all_findings: List[Dict[str, Any]] = code_findings + sec_findings

    # Deduplication: key = (line, rule_id) — same tool+rule on same line
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

    # Sort: by severity rank (ascending = most critical first), then by line number
    merged.sort(key=lambda f: (_severity_rank(f), f.get("line") or 0))

    print(f"[Merge Node] Code Analysis: {len(code_findings)} findings | "
          f"Security: {len(sec_findings)} findings | "
          f"Merged (deduplicated): {len(merged)} findings")

    return {"findings": merged}


# ---------------------------------------------------------------------------
# Build the LangGraph workflow
# ---------------------------------------------------------------------------

workflow = StateGraph(ScanState)

# Register all nodes
workflow.add_node("code_analysis",  code_analysis_node)
workflow.add_node("security_vuln",  security_vuln_node)
workflow.add_node("merge",          merge_node)
workflow.add_node("remediation",    remediation_node)
workflow.add_node("pr_summary",     pr_summary_node)

# Fan-out: START → both agents in parallel
workflow.add_edge(START, "code_analysis")
workflow.add_edge(START, "security_vuln")

# Fan-in: both agents → merge node
workflow.add_edge("code_analysis", "merge")
workflow.add_edge("security_vuln", "merge")

# Sequential post-merge pipeline
workflow.add_edge("merge",       "remediation")
workflow.add_edge("remediation", "pr_summary")
workflow.add_edge("pr_summary",  END)

app = workflow.compile()
