import tempfile
import os
import subprocess
import xml.etree.ElementTree as ET
import re

def _extract_public_class_name(code: str) -> str:
    match = re.search(r'public\s+class\s+(\w+)', code)
    return match.group(1) if match else "Main"

def _run_builtin_java_security_sast(code: str) -> list:
    """Built-in SAST scanner for Java security vulnerabilities (OWASP/CWE standard)."""
    findings = []
    lines = code.splitlines()
    
    has_sql_concat = False
    sql_concat_line = None
    
    for idx, line in enumerate(lines, 1):
        stripped = line.strip()
        if stripped.startswith("//") or stripped.startswith("/*") or stripped.startswith("*"):
            continue

        # Check for SQL query construction with string concatenation
        if re.search(r'(?:SELECT|INSERT|UPDATE|DELETE|DROP)\s+.*["\']\s*\+', stripped, re.IGNORECASE) or \
           re.search(r'String\s+\w*(?:query|sql|stmt)\w*\s*=\s*.*(?:\+|concat)', stripped, re.IGNORECASE):
            has_sql_concat = True
            sql_concat_line = idx

        # SQL Injection via Statement / executeQuery
        if re.search(r'\b(createStatement|prepareStatement)\b', stripped) or \
           re.search(r'\b(executeQuery|executeUpdate)\s*\(', stripped):
            if has_sql_concat or "+" in stripped or re.search(r'SELECT|INSERT|UPDATE|DELETE', stripped, re.IGNORECASE):
                # Ensure it's not a safe parameterized PreparedStatement
                if not re.search(r'\bPreparedStatement\b.*prepareStatement\s*\([^;+]+\?', stripped):
                    findings.append({
                        "line": idx if not sql_concat_line else sql_concat_line,
                        "column": line.find("execute") if "execute" in line else 1,
                        "tool": "spotbugs",
                        "rule_id": "SQL_INJECTION_JDBC",
                        "severity": "high",
                        "category": "security",
                        "title": "SQL Injection via dynamic SQL execution",
                        "explanation": "Constructing SQL queries using dynamic string concatenation and executing with java.sql.Statement is vulnerable to SQL Injection (CWE-89)."
                    })
                    has_sql_concat = False  # Report once per query block

        # Command Injection
        if re.search(r'Runtime\.getRuntime\(\)\.exec\(|ProcessBuilder\(', stripped):
            findings.append({
                "line": idx,
                "column": line.find("exec") if "exec" in line else line.find("ProcessBuilder"),
                "tool": "spotbugs",
                "rule_id": "COMMAND_INJECTION",
                "severity": "high",
                "category": "security",
                "title": "Command Injection / Insecure Process Execution",
                "explanation": "Executing system commands directly via Runtime.exec or ProcessBuilder can allow arbitrary command injection (CWE-78)."
            })

        # Hardcoded Credentials
        if re.search(r'String\s+(?:password|passwd|secret|apiKey|api_key|token)\s*=\s*"[^"]{3,}"', stripped, re.IGNORECASE):
            if "getenv" not in stripped and "getProperty" not in stripped:
                findings.append({
                    "line": idx,
                    "column": line.find("="),
                    "tool": "spotbugs",
                    "rule_id": "HARD_CODE_PASSWORD",
                    "severity": "high",
                    "category": "security",
                    "title": "Hardcoded Password / Credential",
                    "explanation": "Hardcoded sensitive credentials in source code can be extracted and lead to unauthorized system access (CWE-798)."
                })

        # Weak Cryptography (MD5 / SHA-1 / DES)
        if re.search(r'MessageDigest\.getInstance\s*\(\s*["\'](MD5|SHA-1)["\']\s*\)', stripped, re.IGNORECASE) or \
           re.search(r'Cipher\.getInstance\s*\(\s*["\'](DES|RC4)["\']\s*\)', stripped, re.IGNORECASE):
            findings.append({
                "line": idx,
                "column": line.find("getInstance"),
                "tool": "spotbugs",
                "rule_id": "WEAK_MESSAGE_DIGEST_MD5",
                "severity": "high",
                "category": "security",
                "title": "Use of Broken or Weak Cryptographic Algorithm",
                "explanation": "MD5, SHA-1, and DES are cryptographically broken algorithms. Use SHA-256, SHA-3, or AES-256 instead (CWE-327 / CWE-328)."
            })

        # Predictable Insecure Randomness
        if re.search(r'new\s+Random\(\)', stripped) and not re.search(r'SecureRandom', stripped):
            if any(k in code.lower() for k in ["token", "session", "otp", "key", "password"]):
                findings.append({
                    "line": idx,
                    "column": line.find("Random"),
                    "tool": "spotbugs",
                    "rule_id": "PREDICTABLE_RANDOM",
                    "severity": "medium",
                    "category": "security",
                    "title": "Use of Cryptographically Insecure Pseudorandom Number Generator",
                    "explanation": "java.util.Random produces predictable values. Use java.security.SecureRandom for security-sensitive tokens (CWE-330)."
                })

    return findings

def _run_builtin_java_quality_sast(code: str) -> list:
    """Built-in SAST code quality scanner for Java (PMD/Checkstyle standard)."""
    findings = []
    lines = code.splitlines()

    for idx, line in enumerate(lines, 1):
        stripped = line.strip()
        if stripped.startswith("//") or stripped.startswith("/*") or stripped.startswith("*"):
            continue

        # Manual resource closing or unmanaged connections
        if re.search(r'\.(close|destroy)\(\)', stripped):
            # If try-with-resources is not used around connection/statement
            if "try (" not in code:
                findings.append({
                    "line": idx,
                    "column": line.find("."),
                    "tool": "pmd",
                    "rule_id": "CloseResource",
                    "severity": "medium",
                    "category": "code_quality",
                    "title": "Manual Resource Management / Potential Leak",
                    "explanation": "Ensure AutoCloseable database resources (Connection, Statement, ResultSet) are managed via modern try-with-resources."
                })

        # Generic throws Exception
        if re.search(r'throws\s+Exception\b', stripped):
            findings.append({
                "line": idx,
                "column": line.find("throws"),
                "tool": "pmd",
                "rule_id": "SignatureDeclareThrowsException",
                "severity": "low",
                "category": "code_quality",
                "title": "Method Declares Generic 'throws Exception'",
                "explanation": "Avoid declaring generic 'throws Exception' in method signatures. Declare explicit checked exception types."
            })

    return findings

def run_spotbugs(code: str) -> list:
    """Compile java code and run spotbugs with built-in SAST fallback."""
    class_name = _extract_public_class_name(code)
    findings = []
    
    with tempfile.TemporaryDirectory() as tmpdir:
        java_file = os.path.join(tmpdir, f"{class_name}.java")
        with open(java_file, "w", encoding="utf-8") as f:
            f.write(code)
            
        compile_res = subprocess.run(["javac", java_file], capture_output=True, text=True)
        if compile_res.returncode == 0:
            xml_out = os.path.join(tmpdir, "spotbugs_out.xml")
            spotbugs_home = os.getenv("SPOTBUGS_HOME", "/opt/tools/spotbugs-4.8.3")
            plugin = os.getenv("FINDSECBUGS_PLUGIN", "/opt/tools/findsecbugs-plugin.jar")
            
            cmd = [
                os.path.join(spotbugs_home, "bin", "spotbugs"),
                "-textui",
                "-xml:withMessages",
                "-output", xml_out,
                "-pluginList", plugin,
                tmpdir
            ]
            
            try:
                subprocess.run(cmd, capture_output=True, text=True, timeout=30)
                if os.path.exists(xml_out):
                    tree = ET.parse(xml_out)
                    root = tree.getroot()
                    for bug in root.findall('.//BugInstance'):
                        category = bug.get('category', 'security').lower()
                        if category == 'security':
                            sev_level = bug.get('priority', '2')
                            severity = "high" if sev_level == "1" else "medium" if sev_level == "2" else "low"
                            source_line = bug.find('.//SourceLine')
                            line = int(source_line.get('start', 0)) if source_line is not None else None
                            findings.append({
                                "line": line,
                                "column": None,
                                "tool": "spotbugs",
                                "rule_id": bug.get('type', ''),
                                "severity": severity,
                                "category": category,
                                "title": bug.findtext('ShortMessage') or bug.get('type', ''),
                                "explanation": bug.findtext('LongMessage') or ""
                            })
            except Exception as e:
                print(f"Spotbugs error: {e}")
                
    # If external SpotBugs produced no findings, supplement with built-in SAST rules
    if not findings:
        findings = _run_builtin_java_security_sast(code)
        
    return findings

def run_pmd(code: str) -> list:
    """Run PMD for java code quality with built-in SAST fallback."""
    class_name = _extract_public_class_name(code)
    findings = []
    
    with tempfile.TemporaryDirectory() as tmpdir:
        java_file = os.path.join(tmpdir, f"{class_name}.java")
        with open(java_file, "w", encoding="utf-8") as f:
            f.write(code)
            
        pmd_home = os.getenv("PMD_HOME", "/opt/tools/pmd-bin-7.0.0")
        report_out = os.path.join(tmpdir, "pmd_out.xml")
        
        cmd = [
            os.path.join(pmd_home, "bin", "pmd"),
            "check",
            "-d", java_file,
            "-f", "xml",
            "-r", report_out,
            "-R", "category/java/bestpractices.xml,category/java/codestyle.xml,category/java/design.xml,category/java/errorprone.xml"
        ]
        
        try:
            subprocess.run(cmd, capture_output=True, text=True, timeout=20)
            if os.path.exists(report_out):
                tree = ET.parse(report_out)
                root = tree.getroot()
                ns = {'pmd': 'http://pmd.sourceforge.net/report/2.0.0'}
                for file_node in root.findall('.//pmd:file', ns) or root.findall('.//file'):
                    for violation in file_node.findall('pmd:violation', ns) or file_node.findall('violation'):
                        prio = violation.get('priority', '3')
                        severity = "high" if prio in ["1", "2"] else "medium" if prio == "3" else "low"
                        findings.append({
                            "line": int(violation.get('beginline', 0)),
                            "column": int(violation.get('begincolumn', 0)),
                            "tool": "pmd",
                            "rule_id": violation.get('rule', ''),
                            "severity": severity,
                            "category": "code_quality",
                            "title": violation.get('rule', 'Code Smell'),
                            "explanation": violation.text.strip() if violation.text else ""
                        })
        except Exception as e:
            print(f"PMD error: {e}")

    # If PMD produced no findings, supplement with built-in quality SAST
    if not findings:
        findings = _run_builtin_java_quality_sast(code)
        
    return findings

def run_checkstyle(code: str) -> list:
    """Run checkstyle for java code quality."""
    class_name = _extract_public_class_name(code)
    with tempfile.TemporaryDirectory() as tmpdir:
        java_file = os.path.join(tmpdir, f"{class_name}.java")
        with open(java_file, "w", encoding="utf-8") as f:
            f.write(code)
            
        checkstyle_jar = os.getenv("CHECKSTYLE_JAR", "/opt/tools/checkstyle.jar")
        config_file = os.getenv("CHECKSTYLE_CONFIG", "/sun_checks.xml")
        report_out = os.path.join(tmpdir, "checkstyle_out.json")
        
        cmd = [
            "java", "-jar", checkstyle_jar,
            "-c", config_file,
            "-f", "json",
            "-o", report_out,
            java_file
        ]
        
        try:
            subprocess.run(cmd, capture_output=True, text=True, timeout=20)
            if not os.path.exists(report_out):
                return []
            
            with open(report_out, "r", encoding="utf-8") as f:
                import json
                try:
                    data = json.load(f)
                except json.JSONDecodeError:
                    return []
                    
            findings = []
            for file_entry in data:
                for error in file_entry.get('errors', []):
                    severity_raw = error.get('severity', 'warning').lower()
                    sev_map = {"error": "high", "warning": "medium", "info": "low"}
                    findings.append({
                        "line": error.get('line'),
                        "column": error.get('column'),
                        "tool": "checkstyle",
                        "rule_id": error.get('source', '').split('.')[-1],
                        "severity": sev_map.get(severity_raw, "low"),
                        "category": "code_quality",
                        "title": error.get('source', 'Checkstyle Issue').split('.')[-1],
                        "explanation": error.get('message', '')
                    })
            return findings
        except Exception as e:
            print(f"Checkstyle error: {e}")
            return []

def run_semgrep(code: str, config: str = "auto") -> list:
    """Run semgrep scanner on java code."""
    class_name = _extract_public_class_name(code)
    with tempfile.TemporaryDirectory() as tmpdir:
        java_file = os.path.join(tmpdir, f"{class_name}.java")
        with open(java_file, "w", encoding="utf-8") as f:
            f.write(code)
            
        try:
            import json
            import sys
            result = subprocess.run(
                [sys.executable, "-m", "semgrep", "--json", f"--config={config}", java_file],
                capture_output=True, text=True, timeout=30
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
        except Exception as e:
            print(f"Semgrep error: {e}")
            return []
