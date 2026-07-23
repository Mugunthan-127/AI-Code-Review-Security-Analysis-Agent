import ast
import javalang
import subprocess
import tempfile
import os
import re
import shutil
import logging

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Heuristic patterns (fallback layer only)
# ---------------------------------------------------------------------------
JAVA_HEURISTIC_CHECKS = [
    (r'\bSystemout\b',                               "Undefined symbol 'Systemout' — did you mean 'System.out'?"),
    (r'\bsystem\.out\b',                             "Java is case-sensitive — use 'System.out', not 'system.out'"),
    (r'\bsystem\.exit\b',                            "Java is case-sensitive — use 'System.exit()', not 'system.exit()'"),
    (r'(?<![A-Z])\bstring\s+\w+\s*[=;(,)]',         "Java is case-sensitive — use 'String', not 'string'"),
    (r'==\s*"',                                      "Use '.equals()' to compare strings, not '=='"),
    (r'"\s*==',                                      "Use '.equals()' to compare strings, not '=='"),
    (r'public\s+static\s+void\s+main\s*\(\s*\)',     "main() must accept String[] args: 'public static void main(String[] args)'"),
]


# ---------------------------------------------------------------------------
# Python validator
# ---------------------------------------------------------------------------
def validate_python_code(code: str) -> tuple:
    try:
        ast.parse(code)
        return True, None, []
    except SyntaxError as e:
        error_msg = f"Syntax error at line {e.lineno}, offset {e.offset}: {e.msg}\n{e.text}"
        return False, error_msg, [{
            "line": e.lineno,
            "column": e.offset,
            "severity": "error",
            "issue": e.msg,
            "fix": "Review syntax on this line — check indentation, colons, parentheses, and quotes.",
            "snippet": e.text or ""
        }]
    except Exception as e:
        return False, f"Validation failed: {str(e)}", []


# ---------------------------------------------------------------------------
# Java validator helpers
# ---------------------------------------------------------------------------
def _javac_available() -> bool:
    return shutil.which("javac") is not None


def _extract_public_class_name(code: str) -> str:
    match = re.search(r'public\s+class\s+(\w+)', code)
    return match.group(1) if match else "Main"


def _suggest_fix(message: str, snippet: str) -> str:
    msg = message.lower()
    if "cannot find symbol" in msg:
        sym = re.search(r'symbol:\s*(class|variable|method)\s+(\w+)', message, re.IGNORECASE)
        name = sym.group(2) if sym else "the symbol"
        if name.lower() == "systemout":
            return "Replace 'Systemout' with 'System.out' — Java class names are case-sensitive."
        if name[0].islower() and name not in ("args", "this", "super"):
            return f"'{name}' is not defined. Check spelling, import the class, or declare the variable before use."
        return f"'{name}' cannot be found. Check spelling, imports, or variable declarations."
    if "';' expected" in msg:
        return "Add a semicolon ';' at the end of the statement on this line."
    if "illegal start of expression" in msg:
        return "Check for mismatched braces '{}', unmatched parentheses, or a misplaced keyword."
    if "reached end of file" in msg:
        return "A closing brace '}' is missing. Make sure every opened '{' has a matching '}'."
    if "incompatible types" in msg:
        return "You are assigning or passing a value of the wrong type. Check variable declarations and method signatures."
    if "class" in msg and "public" in msg:
        return "The public class name must exactly match the filename (case-sensitive)."
    if "might not have been initialized" in msg:
        return "Initialize the variable before using it (e.g., `int x = 0;` instead of `int x;`)."
    if "unclosed string literal" in msg:
        return "A string literal is missing its closing quote `\"`. Check this line for an unmatched `\"`."
    return "Review the code at this line and correct the syntax or logic error indicated above."


def _parse_javac_errors(stderr: str, class_name: str) -> list[dict]:
    errors = []
    pattern = re.compile(
        rf'{re.escape(class_name)}\.java:(\d+):\s*(error|warning|note):\s*(.+)'
    )
    lines = stderr.strip().splitlines()
    i = 0
    while i < len(lines):
        m = pattern.match(lines[i].strip())
        if m:
            line_no  = int(m.group(1))
            severity = m.group(2)
            message  = m.group(3).strip()
            snippet  = lines[i + 1].strip() if i + 1 < len(lines) else ""
            caret    = lines[i + 2].strip() if i + 2 < len(lines) else ""
            col_no   = caret.index("^") + 1 if "^" in caret else None
            errors.append({
                "line":     line_no,
                "column":   col_no,
                "severity": severity,
                "issue":    message,
                "fix":      _suggest_fix(message, snippet),
                "snippet":  snippet,
            })
            i += 3
        else:
            i += 1
    return errors


def _validate_java_with_javac(code: str) -> tuple:
    class_name = _extract_public_class_name(code)
    try:
        with tempfile.TemporaryDirectory() as tmpdir:
            filepath = os.path.join(tmpdir, f"{class_name}.java")
            with open(filepath, "w", encoding="utf-8") as f:
                f.write(code)
            result = subprocess.run(
                ["javac", filepath], capture_output=True, text=True, timeout=15
            )
            if result.returncode == 0:
                return True, None, []
            stderr = result.stderr.replace(filepath, f"{class_name}.java")
            errors = _parse_javac_errors(stderr, class_name)
            return False, stderr.strip(), errors
    except subprocess.TimeoutExpired:
        msg = "Compilation timed out (>15 s). Check for infinite loops or excessive code size."
        return False, msg, [{"line": None, "column": None, "severity": "error", "issue": msg, "fix": "Reduce code complexity or remove infinite loops.", "snippet": ""}]
    except FileNotFoundError:
        logger.warning("javac vanished mid-run; falling back to javalang.")
        return None, None, []
    except Exception as e:
        logger.error("Unexpected error running javac: %s", e)
        msg = f"Internal compilation error: {str(e)}"
        return False, msg, [{"line": None, "column": None, "severity": "error", "issue": msg, "fix": "Contact support.", "snippet": ""}]


def _validate_java_with_javalang(code: str) -> tuple:
    try:
        javalang.parse.parse(code)
    except javalang.parser.JavaSyntaxError as e:
        msg = f"Java syntax error: {str(e)}"
        line_match = re.search(r'line (\d+)', str(e), re.IGNORECASE)
        line_no = int(line_match.group(1)) if line_match else None
        return False, msg, [{
            "line": line_no, "column": None, "severity": "error",
            "issue": msg,
            "fix": "Check the syntax around this line for missing semicolons, braces, or keywords.",
            "snippet": "",
        }]
    except Exception as e:
        msg = f"Validation failed: {str(e)}"
        return False, msg, [{"line": None, "column": None, "severity": "error", "issue": msg, "fix": "Review the full file for syntax issues.", "snippet": ""}]

    code_lines = code.splitlines()
    errors = []
    HEURISTIC_WITH_FIXES = [
        (r'\bSystemout\b',
         "Undefined symbol 'Systemout'",
         "Replace 'Systemout' with 'System.out' — Java is case-sensitive."),
        (r'\bsystem\.out\b',
         "Incorrect casing: 'system.out'",
         "Use 'System.out' (capital S) — Java class names are case-sensitive."),
        (r'\bsystem\.exit\b',
         "Incorrect casing: 'system.exit'",
         "Use 'System.exit()' (capital S) — Java class names are case-sensitive."),
        (r'(?<![A-Z])\bstring\s+\w+\s*[=;(,)]',
         "Incorrect type name 'string'",
         "Use 'String' (capital S) — Java primitive wrappers are capitalized."),
        (r'==\s*"',
         "String comparison with '=='",
         "Use str.equals(\"...\") instead of '==' to compare String values."),
        (r'"\s*==',
         "String comparison with '=='",
         "Use str.equals(\"...\") instead of '==' to compare String values."),
        (r'public\s+static\s+void\s+main\s*\(\s*\)',
         "Invalid main() signature — missing String[] args",
         "Change to: public static void main(String[] args)"),
    ]
    for i, src_line in enumerate(code_lines, start=1):
        for pattern, issue, fix in HEURISTIC_WITH_FIXES:
            if re.search(pattern, src_line):
                errors.append({
                    "line": i, "column": None, "severity": "error",
                    "issue": issue, "fix": fix, "snippet": src_line.strip(),
                })

    if errors:
        return False, "; ".join(e["issue"] for e in errors), errors
    return True, None, []


def validate_java_code(code: str) -> tuple:
    if _javac_available():
        is_valid, raw, errors = _validate_java_with_javac(code)
        if is_valid is not None:
            return is_valid, raw, errors
    logger.info("javac unavailable — using javalang + heuristic fallback.")
    return _validate_java_with_javalang(code)


def validate_code(code: str, language: str) -> tuple:
    """
    Returns (is_valid, raw_message, structured_errors).
    structured_errors is a list of dicts: {line, column, severity, issue, fix, snippet, owasp_id, cwe_id}
    """
    lang = language.lower()
    if lang == "python":
        is_valid, msg, errors = validate_python_code(code)
    elif lang == "java":
        is_valid, msg, errors = validate_java_code(code)
    else:
        msg = f"Unsupported language: {language}"
        return False, msg, [{"line": None, "column": None, "severity": "error", "issue": msg, "fix": "Choose 'python' or 'java'.", "snippet": ""}]
    return is_valid, msg, errors
