import tempfile
import os
import subprocess
import json
import sys

def run_bandit(code: str) -> list:
    """Run bandit security scanner on Python code."""
    with tempfile.NamedTemporaryFile(suffix=".py", delete=False, mode="w", encoding="utf-8") as f:
        f.write(code)
        temp_path = f.name
    try:
        result = subprocess.run(
            [sys.executable, "-m", "bandit", "-f", "json", temp_path],
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
        f.write(code.replace('\r', ''))
        temp_path = f.name
    try:
        result = subprocess.run(
            [sys.executable, "-m", "pylint", "--output-format=json", temp_path],
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

def run_ruff(code: str) -> list:
    """Run ruff quality scanner on Python code."""
    with tempfile.NamedTemporaryFile(suffix=".py", delete=False, mode="w", encoding="utf-8") as f:
        f.write(code.replace('\r', ''))
        temp_path = f.name
    try:
        result = subprocess.run(
            [sys.executable, "-m", "ruff", "check", "--output-format=json", temp_path],
            capture_output=True, text=True
        )
        try:
            data = json.loads(result.stdout)
            findings = []
            for item in data:
                # Ruff usually just returns diagnostics without severity, we map by convention or default to medium
                findings.append({
                    "line": item.get("location", {}).get("row"),
                    "column": item.get("location", {}).get("column"),
                    "tool": "ruff",
                    "rule_id": item.get("code"),
                    "severity": "medium", # Defaulting to medium for Ruff, can be adjusted based on rule prefix
                    "category": "code_quality",
                    "title": item.get("code", "Code Smell"),
                    "explanation": item.get("message", "")
                })
            return findings
        except json.JSONDecodeError:
            return []
    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)

def run_semgrep(code: str, config: str = "auto") -> list:
    """Run semgrep scanner on code."""
    with tempfile.NamedTemporaryFile(suffix=".py", delete=False, mode="w", encoding="utf-8") as f:
        f.write(code.replace('\r', ''))
        temp_path = f.name
    try:
        result = subprocess.run(
            [sys.executable, "-m", "semgrep", "--json", f"--config={config}", temp_path],
            capture_output=True, text=True
        )
        try:
            data = json.loads(result.stdout)
            findings = []
            for item in data.get("results", []):
                extra = item.get("extra", {})
                severity_raw = extra.get("severity", "WARNING").lower()
                sev_map = {"error": "high", "warning": "medium", "info": "low"}
                findings.append({
                    "line": item.get("start", {}).get("line"),
                    "column": item.get("start", {}).get("col"),
                    "tool": "semgrep",
                    "rule_id": item.get("check_id"),
                    "severity": sev_map.get(severity_raw, "low"),
                    "category": "security" if "security" in config else "code_quality",
                    "title": item.get("check_id", "Semgrep Finding").split(".")[-1],
                    "explanation": extra.get("message", "")
                })
            return findings
        except json.JSONDecodeError:
            return []
    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)
