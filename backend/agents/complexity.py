import re
import ast
from typing import Dict, Any
from .state import ScanState

def _cyclomatic_complexity(code: str) -> int:
    """
    Approximate cyclomatic complexity:
    Count decision points: if, elif, for, while, and, or, except, case/when, catch, ternary, logical operators.
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

def _control_nesting_python(code: str) -> int:
    """Calculate maximum control-flow nesting depth in Python via AST."""
    try:
        tree = ast.parse(code)
    except Exception:
        return 0

    max_depth = 0

    def walk_node(node, current_depth):
        nonlocal max_depth
        is_control = isinstance(node, (ast.If, ast.For, ast.While, getattr(ast, 'Match', ())))
        new_depth = current_depth + 1 if is_control else current_depth
        max_depth = max(max_depth, new_depth)
        for child in ast.iter_child_nodes(node):
            walk_node(child, new_depth)

    walk_node(tree, 0)
    return max_depth

def _control_nesting_java(code: str) -> int:
    """
    Calculate maximum control-flow nesting depth in Java.
    Only counts nested decision/loop structures: if, for, while, switch, do-while.
    Ignores structural scaffolding: class, interface, method, try, catch, finally, try-with-resources.
    """
    cleaned = re.sub(r'//.*', '', code)
    cleaned = re.sub(r'/\*.*?\*/', '', cleaned, flags=re.DOTALL)
    
    tokens = re.findall(r'(\bif\b|\bfor\b|\bwhile\b|\bswitch\b|\bdo\b|\btry\b|\bcatch\b|\bfinally\b|\bclass\b|\binterface\b|\{|\})', cleaned)
    
    max_control_depth = 0
    block_stack = []
    pending_control = False
    
    for token in tokens:
        if token in ('if', 'for', 'while', 'switch', 'do'):
            pending_control = True
        elif token in ('try', 'catch', 'finally', 'class', 'interface'):
            pending_control = False
        elif token == '{':
            if pending_control:
                block_stack.append('control')
                pending_control = False
            else:
                block_stack.append('structural')
            
            control_count = block_stack.count('control')
            max_control_depth = max(max_control_depth, control_count)
        elif token == '}':
            if block_stack:
                block_stack.pop()
            pending_control = False
            
    return max_control_depth

def _max_nesting_depth(code: str, lang: str = "python") -> int:
    """Calculate language-aware control flow nesting depth."""
    if lang.lower() == "java" or "class " in code and ";" in code:
        return _control_nesting_java(code)
    else:
        py_depth = _control_nesting_python(code)
        if py_depth > 0:
            return py_depth
        return _control_nesting_java(code)

def _count_functions(code: str) -> int:
    """Count number of function/method definitions."""
    return len(re.findall(r'\b(def |public |private |protected |static )\s*\w+\s*\(', code))

def complexity_node(state: ScanState) -> Dict[str, Any]:
    """
    Complexity Node - Analyzes code complexity using cyclomatic complexity,
    control-flow nesting depth, and function length metrics.
    """
    code = state.get("code", "")
    lang = state.get("language", "python")
    findings = []

    cc = _cyclomatic_complexity(code)
    depth = _max_nesting_depth(code, lang)
    lines = [l for l in code.splitlines() if l.strip()]
    total_lines = len(lines)
    func_count = _count_functions(code)
    avg_func_len = total_lines // max(func_count, 1)

    # Finding 1: Cyclomatic complexity (CC <= 10 is standard/clean, CC >= 15 is high)
    if cc >= 25:
        findings.append({
            "agent_source": "complexity",
            "title": "Critical Cyclomatic Complexity",
            "tool": "complexity_scanner",
            "rule_id": "COMP-001",
            "severity": "high",
            "category": "maintainability",
            "explanation": (
                f"Cyclomatic complexity score is {cc}. "
                f"Scores above 20 indicate dense execution branching that is error-prone and hard to unit test."
            ),
            "suggested_fix": (
                "Decompose complex branching into smaller, single-responsibility functions or apply polymorphism / strategy pattern."
            ),
            "line": 1
        })
    elif cc >= 15:
        findings.append({
            "agent_source": "complexity",
            "title": "High Cyclomatic Complexity",
            "tool": "complexity_scanner",
            "rule_id": "COMP-001",
            "severity": "medium",
            "category": "maintainability",
            "explanation": (
                f"Cyclomatic complexity score is {cc}. "
                f"Scores above 15 indicate methods with multiple decision branches that should be refactored for clarity."
            ),
            "suggested_fix": (
                "Decompose complex branching into smaller helper functions. Aim for a cyclomatic complexity below 10 per method."
            ),
            "line": 1
        })

    # Finding 2: Excessive control-flow nesting (depth >= 4 of nested loops/conditions)
    if depth >= 4:
        findings.append({
            "agent_source": "complexity",
            "title": "Excessive Nesting Depth",
            "tool": "complexity_scanner",
            "rule_id": "COMP-002",
            "severity": "medium" if depth >= 5 else "low",
            "category": "maintainability",
            "explanation": (
                f"Maximum control-flow nesting depth is {depth} levels of nested conditions/loops. "
                "Deeply nested control structures increase cognitive load and hinder test coverage."
            ),
            "suggested_fix": (
                "Apply guard clauses (early return pattern) and extract deeply nested loop/branch bodies into dedicated helper methods."
            ),
            "line": 1
        })

    # Finding 3: Long files (> 300 non-blank lines or avg function > 60 lines)
    if total_lines > 300 or (func_count > 0 and avg_func_len > 60):
        findings.append({
            "agent_source": "complexity",
            "title": "Large File / Long Function Scope",
            "tool": "complexity_scanner",
            "rule_id": "COMP-003",
            "severity": "low",
            "category": "maintainability",
            "explanation": (
                f"File contains {total_lines} non-blank lines "
                f"{'with an average function length of ' + str(avg_func_len) + ' lines. ' if func_count > 0 else '. '}"
                "Large functions are difficult to comprehend and maintain."
            ),
            "suggested_fix": (
                "Split oversized functions into modular helper functions adhering to the Single Responsibility Principle (SRP)."
            ),
            "line": 1
        })

    print(f"[Complexity Node] CC={cc}, control_depth={depth}, lines={total_lines} -> {len(findings)} findings")
    return {"complexity_findings": findings}


