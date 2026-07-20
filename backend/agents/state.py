"""
Shared state definition for the LangGraph scan pipeline.
Uses Annotated reducer functions so parallel nodes can write to separate
output keys without conflict, which LangGraph then merges correctly.
"""
from typing import TypedDict, List, Dict, Any, Optional


class ScanState(TypedDict):
    # ── Inputs (set by submission router) ──────────────────────────────────
    scan_id: str
    code: str
    language: str  # 'python' or 'java'

    # ── Parallel agent outputs (each agent writes to its own key) ──────────
    code_analysis_findings: List[Dict[str, Any]]
    security_findings: List[Dict[str, Any]]

    # ── Merged output (written by merge node) ─────────────────────────────
    findings: List[Dict[str, Any]]

    # ── Downstream agent outputs ───────────────────────────────────────────
    summary_text: Optional[str]
