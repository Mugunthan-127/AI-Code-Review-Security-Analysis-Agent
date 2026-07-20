import tempfile
import os
import subprocess
import json

def run_bandit(code: str) -> list:
    """Run bandit security scanner on Python code."""
    with tempfile.NamedTemporaryFile(suffix=".py", delete=False, mode="w", encoding="utf-8") as f:
        f.write(code)
        temp_path = f.name
    try:
        result = subprocess.run(
            ["bandit", "-f", "json", temp_path],
            capture_output=True, text=True
        )
        try:
            data = json.loads(result.stdout)
            findings = []
            for item in data.get("results", []):
                findings.append({
                    "line": item.get("line_number"),
                    "column": None,
                    "tool": "bandit",
                    "rule_id": item.get("test_id"),
                    "severity": item.get("issue_severity", "LOW").lower(),
                    "category": "security",
                    "title": item.get("test_name", "Security Issue"),
                    "explanation": item.get("issue_text", ""),
                    "cwe_id": f"CWE-{item.get('issue_cwe', {}).get('id', '')}" if item.get('issue_cwe') and item.get('issue_cwe').get('id') else None
                })
            return findings
        except json.JSONDecodeError:
            return []
    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)

def run_pylint(code: str) -> list:
    """Run pylint quality scanner on Python code."""
    with tempfile.NamedTemporaryFile(suffix=".py", delete=False, mode="w", encoding="utf-8") as f:
        f.write(code)
        temp_path = f.name
    try:
        result = subprocess.run(
            ["pylint", "--output-format=json", temp_path],
            capture_output=True, text=True
        )
        try:
            data = json.loads(result.stdout)
            findings = []
            for item in data:
                type_map = {"fatal": "critical", "error": "high", "warning": "medium", "convention": "low", "refactor": "low"}
                severity = type_map.get(item.get("type", "warning"), "low")
                findings.append({
                    "line": item.get("line"),
                    "column": item.get("column"),
                    "tool": "pylint",
                    "rule_id": item.get("message-id"),
                    "severity": severity,
                    "category": "code_quality",
                    "title": item.get("symbol", "Code Smell"),
                    "explanation": item.get("message", "")
                })
            return findings
        except json.JSONDecodeError:
            return []
    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)
