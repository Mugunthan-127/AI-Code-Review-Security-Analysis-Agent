"""
Standalone validation runner — Milestone 2
Runs Bandit + Pylint directly on the test sample files and records results.
Does NOT require PostgreSQL or the FastAPI server to be running.
"""
import subprocess
import json
import sys
import os
import tempfile
import shutil

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TEST_DIR = os.path.join(BASE_DIR, "tests")
PYTHON_SAMPLE = os.path.join(TEST_DIR, "sample_python_vulnerabilities.py")

# ── Ground truth for Python sample ─────────────────────────────────────────
GROUND_TRUTH_PYTHON = [
    {"id": 1,  "line": 15, "agent": "security_vulnerability", "owasp_type": "Hardcoded Credentials", "severity": "high",   "desc": "DATABASE_PASSWORD hardcoded"},
    {"id": 2,  "line": 16, "agent": "security_vulnerability", "owasp_type": "Hardcoded Credentials", "severity": "high",   "desc": "API_KEY hardcoded"},
    {"id": 3,  "line": 30, "agent": "security_vulnerability", "owasp_type": "SQL Injection",          "severity": "high",   "desc": "f-string in cursor.execute()"},
    {"id": 4,  "line": 44, "agent": "security_vulnerability", "owasp_type": "Command Injection",      "severity": "high",   "desc": "subprocess shell=True"},
    {"id": 5,  "line": 54, "agent": "security_vulnerability", "owasp_type": "Unsafe Deserialization", "severity": "high",   "desc": "pickle.loads()"},
    {"id": 6,  "line": 64, "agent": "security_vulnerability", "owasp_type": "Insecure Cryptography",  "severity": "high",   "desc": "hashlib.md5() for passwords"},
    {"id": 7,  "line": 73, "agent": "code_analysis",          "owasp_type": None,                     "severity": "high",   "desc": "Mutable default argument"},
    {"id": 8,  "line": 82, "agent": "code_analysis",          "owasp_type": None,                     "severity": "medium", "desc": "Too many branches"},
    {"id": 9,  "line": 82, "agent": "code_analysis",          "owasp_type": None,                     "severity": "medium", "desc": "Too many arguments"},
    {"id": 10, "line": 122,"agent": "code_analysis",          "owasp_type": None,                     "severity": "high",   "desc": "Broad exception catch (except Exception)"},
]

BANDIT_OWASP_MAP = {
    "B105": ("Hardcoded Credentials",    "CWE-798", "high"),
    "B106": ("Hardcoded Credentials",    "CWE-798", "high"),
    "B107": ("Hardcoded Credentials",    "CWE-798", "medium"),
    "B608": ("SQL Injection",            "CWE-89",  "high"),
    "B602": ("Command Injection",        "CWE-78",  "high"),
    "B603": ("Command Injection",        "CWE-78",  "medium"),
    "B604": ("Command Injection",        "CWE-78",  "high"),
    "B605": ("Command Injection",        "CWE-78",  "high"),
    "B301": ("Unsafe Deserialization",   "CWE-502", "high"),
    "B302": ("Unsafe Deserialization",   "CWE-502", "high"),
    "B303": ("Insecure Cryptography",    "CWE-327", "high"),
    "B324": ("Insecure Cryptography",    "CWE-328", "medium"),
}

PYLINT_SEV_OVERRIDES = {
    "W0102": "high",   # dangerous-default-value
    "W0703": "high",   # broad-except
    "W0702": "high",   # bare-except
    "R0912": "medium", # too-many-branches
    "R0913": "medium", # too-many-arguments
    "R0914": "medium", # too-many-locals
    "R0915": "medium", # too-many-statements
}

PYLINT_TYPE_MAP = {
    "fatal": "critical", "error": "high", "warning": "medium",
    "convention": "low",  "refactor": "medium",
}

SEP = "─" * 70

def run_bandit(filepath):
    result = subprocess.run(
        ["bandit", "-f", "json", "-q", filepath],
        capture_output=True, text=True
    )
    try:
        data = json.loads(result.stdout)
        findings = []
        for item in data.get("results", []):
            rule_id = item.get("test_id", "")
            mapping = BANDIT_OWASP_MAP.get(rule_id)
            owasp_type = mapping[0] if mapping else "Security Vulnerability"
            cwe_id     = mapping[1] if mapping else None
            severity   = (mapping[2] if mapping else item.get("issue_severity","LOW")).lower()
            findings.append({
                "line":       item.get("line_number"),
                "rule_id":    rule_id,
                "severity":   severity,
                "owasp_type": owasp_type,
                "cwe_id":     cwe_id,
                "title":      item.get("test_name",""),
                "agent":      "security_vulnerability",
                "tool":       "bandit",
            })
        return findings
    except Exception as e:
        print(f"  Bandit parse error: {e}")
        return []

def run_pylint(filepath):
    result = subprocess.run(
        ["pylint", "--output-format=json", "--disable=C0114,C0115,C0116,C0301", filepath],
        capture_output=True, text=True
    )
    try:
        data = json.loads(result.stdout)
        findings = []
        for item in data:
            rule_id  = item.get("message-id","")
            msg_type = item.get("type","convention")
            severity = PYLINT_SEV_OVERRIDES.get(rule_id, PYLINT_TYPE_MAP.get(msg_type,"low"))
            findings.append({
                "line":     item.get("line"),
                "rule_id":  rule_id,
                "severity": severity,
                "title":    item.get("symbol",""),
                "agent":    "code_analysis",
                "tool":     "pylint",
            })
        return findings
    except Exception as e:
        print(f"  Pylint parse error: {e}")
        return []

def match_finding(ground_truth, all_findings, line_tolerance=5):
    """Try to match a ground-truth item against actual findings within line_tolerance."""
    for f in all_findings:
        if f.get("agent") != ground_truth["agent"]:
            continue
        actual_line = f.get("line") or 0
        expected_line = ground_truth["line"]
        line_ok = abs(actual_line - expected_line) <= line_tolerance
        # For security: match on owasp_type or rule-level similarity
        if ground_truth["agent"] == "security_vulnerability":
            owasp_ok = (
                f.get("owasp_type","").lower() == (ground_truth.get("owasp_type") or "").lower()
            )
            if owasp_ok and line_ok:
                return f
        else:
            # Code quality: match on rule category (severity + line proximity)
            desc_lower = ground_truth["desc"].lower()
            title_lower = f.get("title","").lower()
            # fuzzy keyword match
            keywords = desc_lower.replace("-","").split()
            title_match = any(k in title_lower for k in keywords[:3])
            if title_match and line_ok:
                return f
            # Also match by rule_id for common pylint codes
            rule_keywords = {
                "W0102": "mutable",
                "R0912": "branch",
                "R0913": "argument",
                "W0703": "exception",
                "W0702": "exception",
            }
            for rid, kw in rule_keywords.items():
                if rid == f.get("rule_id") and kw in desc_lower:
                    return f
    return None

def score_results(ground_truth_list, bandit_findings, pylint_findings):
    all_findings = bandit_findings + pylint_findings
    results = []
    for gt in ground_truth_list:
        match = match_finding(gt, all_findings)
        severity_match = False
        if match:
            severity_match = match.get("severity","").lower() == gt["severity"].lower()
        results.append({
            "gt": gt,
            "found": match is not None,
            "match": match,
            "severity_ok": severity_match,
        })
    return results

def print_section(title):
    print(f"\n{SEP}")
    print(f"  {title}")
    print(SEP)

def run_python_validation():
    print_section("PYTHON VALIDATION — sample_python_vulnerabilities.py")
    print(f"  File: {PYTHON_SAMPLE}\n")

    if not os.path.exists(PYTHON_SAMPLE):
        print(f"  ERROR: Test file not found at {PYTHON_SAMPLE}")
        return None, None, None

    print("  ── Running Bandit (Security Agent)...")
    bandit = run_bandit(PYTHON_SAMPLE)
    print(f"     Found {len(bandit)} raw findings\n")
    for f in bandit:
        print(f"     [{f['rule_id']}] Line {f['line']:>3} | {f['severity'].upper():>8} | {f['owasp_type']} | {f['title']}")

    print("\n  ── Running Pylint (Code Analysis Agent)...")
    pylint = run_pylint(PYTHON_SAMPLE)
    print(f"     Found {len(pylint)} raw findings\n")
    for f in pylint:
        print(f"     [{f['rule_id']}] Line {f['line']:>3} | {f['severity'].upper():>8} | {f['title']}")

    # Score
    print("\n  ── Scoring against ground truth...")
    results = score_results(GROUND_TRUTH_PYTHON, bandit, pylint)

    true_positives  = sum(1 for r in results if r["found"])
    false_negatives = sum(1 for r in results if not r["found"])
    false_positives = max(0, (len(bandit) + len(pylint)) - true_positives)
    recall    = true_positives / len(GROUND_TRUTH_PYTHON) * 100
    precision = true_positives / (true_positives + false_positives) * 100 if (true_positives + false_positives) > 0 else 0

    print(f"\n  {'#':<4} {'GT Line':<9} {'Agent':<22} {'Expected':<26} {'Found?':<8} {'Sev OK?':<8} {'Actual Line'}")
    print(f"  {'─'*4} {'─'*9} {'─'*22} {'─'*26} {'─'*8} {'─'*8} {'─'*11}")
    for r in results:
        gt = r["gt"]
        found_str = "✅ YES" if r["found"] else "❌ NO"
        sev_str   = "✅" if r["severity_ok"] else ("⚠️" if r["found"] else "—")
        act_line  = r["match"].get("line","—") if r["match"] else "—"
        print(f"  {gt['id']:<4} {gt['line']:<9} {gt['agent']:<22} {(gt.get('owasp_type') or gt['desc'])[:25]:<26} {found_str:<8} {sev_str:<8} {act_line}")

    print(f"\n  ┌────────────────────────────────────────┐")
    print(f"  │  Ground-truth issues   : {len(GROUND_TRUTH_PYTHON):>3}            │")
    print(f"  │  True Positives (found): {true_positives:>3}            │")
    print(f"  │  False Negatives       : {false_negatives:>3}            │")
    print(f"  │  False Positives (est.): {false_positives:>3}            │")
    print(f"  │  Recall                : {recall:>5.1f}%          │")
    print(f"  │  Precision             : {precision:>5.1f}%          │")
    print(f"  └────────────────────────────────────────┘")

    return results, bandit, pylint

def main():
    print("\n" + "═"*70)
    print("  MILESTONE 2 — AGENT DETECTION ACCURACY VALIDATION")
    print("  AI Code Review & Security Analysis Agent")
    print("═"*70)

    # Check tools available
    bandit_ok = shutil.which("bandit") is not None
    pylint_ok = shutil.which("pylint") is not None
    print(f"\n  Tool availability:")
    print(f"    bandit : {'✅ found' if bandit_ok else '❌ not found'}")
    print(f"    pylint : {'✅ found' if pylint_ok else '❌ not found'}")

    if not bandit_ok or not pylint_ok:
        print("\n  ❌ Required tools not found. Run: pip install bandit pylint")
        sys.exit(1)

    py_results, bandit_f, pylint_f = run_python_validation()

    print("\n" + "═"*70)
    print("  VALIDATION COMPLETE")
    print("═"*70 + "\n")

    return py_results

if __name__ == "__main__":
    main()
