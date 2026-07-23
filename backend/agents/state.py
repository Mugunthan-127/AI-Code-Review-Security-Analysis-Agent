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

    # ── Validation outputs ─────────────────────────────────────────────────
    is_valid: bool
    validation_error: Optional[str]
    syntax_errors: List[Dict[str, Any]]

    # ── Parallel agent outputs (each agent writes to its own key) ──────────
    code_analysis_findings: List[Dict[str, Any]]
    security_findings: List[Dict[str, Any]]
    complexity_findings: List[Dict[str, Any]]
    dependency_findings: List[Dict[str, Any]]
    license_findings: List[Dict[str, Any]]

    # ── Merged output (written by merge node) ─────────────────────────────
    findings: List[Dict[str, Any]]

    # ── Downstream agent outputs ───────────────────────────────────────────
    risk_score: Optional[int]
    summary_text: Optional[str]
