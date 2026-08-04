import re
from typing import Dict, Any
from .state import ScanState

def _cyclomatic_complexity(code: str) -> int:
    """
    Approximate cyclomatic complexity:
    Count decision points: if, elif, for, while, and, or, except, case/when
    McCabe CC = decision points + 1
    """
    keywords = [
        r'\bif\b', r'\belif\b', r'\bfor\b', r'\bwhile\b',
        r'\band\b', r'\bor\b', r'\bexcept\b', r'\bcase\b',
        r'\bswitch\b', r'\bcatch\b', r'\b\?\s*:', r'\b&&\b', r'\b\|\|\b',
    ]
    count = 1  # base complexity
    for kw in keywords:
        count += len(re.findall(kw, code))
    return count

def _max_nesting_depth(code: str) -> int:
    """Count max indentation depth (proxy for nesting level)."""
    max_depth = 0
    for line in code.splitlines():
        stripped = line.lstrip()
        if not stripped or stripped.startswith('#') or stripped.startswith('//'):
            continue
        spaces = len(line) - len(stripped)
        # 4 spaces or 1 tab per level
        depth = spaces // 4 + line[:spaces].count('\t')
        max_depth = max(max_depth, depth)
    return max_depth

def _count_functions(code: str) -> int:
    """Count number of function/method definitions."""
    return len(re.findall(r'\b(def |public |private |protected |static )\s*\w+\s*\(', code))

def complexity_node(state: ScanState) -> Dict[str, Any]:
    """
    Complexity Node - Analyzes code complexity using cyclomatic complexity,
    nesting depth, and function length metrics.
    """
    code = state.get("code", "")
    findings = []

    cc = _cyclomatic_complexity(code)
    depth = _max_nesting_depth(code)
    lines = [l for l in code.splitlines() if l.strip()]
    total_lines = len(lines)
    func_count = _count_functions(code)
    avg_func_len = total_lines // max(func_count, 1)

    # Finding 1: High cyclomatic complexity
    if cc >= 10:
        findings.append({
            "agent_source": "complexity",
            "title": "High Cyclomatic Complexity",
            "tool": "complexity_scanner",
            "rule_id": "COMP-001",
            "severity": "high" if cc >= 20 else "medium",
            "category": "maintainability",
            "explanation": (
                f"Cyclomatic complexity score is {cc}. "
                f"Scores above 10 indicate code that is hard to test and maintain. "
                f"High complexity means more potential execution paths, each requiring its own test case."
            ),
            "suggested_fix": (
                "Decompose the logic into smaller, single-responsibility functions. "
                "Aim for a cyclomatic complexity below 10 per method/function."
            ),
            "line": 1
        })
    elif cc >= 5:
        findings.append({
            "agent_source": "complexity",
            "title": "Moderate Cyclomatic Complexity",
            "tool": "complexity_scanner",
            "rule_id": "COMP-001",
            "severity": "low",
            "category": "maintainability",
            "explanation": (
                f"Cyclomatic complexity score is {cc}. "
                "This is within acceptable range but watch for growth."
            ),
            "suggested_fix": "Monitor this file as complexity may grow. Consider splitting complex methods.",
            "line": 1
        })

    # Finding 2: Deep nesting
    if depth >= 4:
        findings.append({
            "agent_source": "complexity",
            "title": "Excessive Nesting Depth",
            "tool": "complexity_scanner",
            "rule_id": "COMP-002",
            "severity": "medium" if depth >= 5 else "low",
            "category": "maintainability",
            "explanation": (
                f"Maximum nesting depth is {depth} levels. "
                "Deeply nested code is hard to read, debug, and test. "
                "Each additional nesting level exponentially increases cognitive load."
            ),
            "suggested_fix": (
                "Apply the 'early return' pattern to remove nesting. "
                "Extract deeply nested blocks into separate functions. "
                "Consider replacing nested ifs with guard clauses."
            ),
            "line": 1
        })

    # Finding 3: Long functions / large file
    if total_lines > 100:
        findings.append({
            "agent_source": "complexity",
            "title": "Large Code Block / Long File",
            "tool": "complexity_scanner",
            "rule_id": "COMP-003",
            "severity": "low",
            "category": "maintainability",
            "explanation": (
                f"File contains {total_lines} non-blank lines. "
                f"{'Average function length is ' + str(avg_func_len) + ' lines. ' if func_count > 0 else ''}"
                "Large files and long functions are harder to understand and maintain."
            ),
            "suggested_fix": (
                "Split large files into smaller modules by responsibility. "
                "Functions should ideally be under 30 lines."
            ),
            "line": 1
        })

    print(f"[Complexity Node] CC={cc}, depth={depth}, lines={total_lines} -> {len(findings)} findings")
    return {"complexity_findings": findings}

