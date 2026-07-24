import tempfile
import os
import subprocess
import xml.etree.ElementTree as ET
import re

def _extract_public_class_name(code: str) -> str:
    match = re.search(r'public\s+class\s+(\w+)', code)
    return match.group(1) if match else "Main"

def run_spotbugs(code: str) -> list:
    """Compile java code and run spotbugs."""
    class_name = _extract_public_class_name(code)
    with tempfile.TemporaryDirectory() as tmpdir:
        java_file = os.path.join(tmpdir, f"{class_name}.java")
        with open(java_file, "w", encoding="utf-8") as f:
            f.write(code)
            
        # Compile
        compile_res = subprocess.run(["javac", java_file], capture_output=True, text=True)
        if compile_res.returncode != 0:
            return [] # Can't run spotbugs on uncompilable code
            
        xml_out = os.path.join(tmpdir, "spotbugs_out.xml")
        spotbugs_home = os.getenv("SPOTBUGS_HOME", "/opt/tools/spotbugs-4.8.3")
        plugin = os.getenv("FINDSECBUGS_PLUGIN", "/opt/tools/findsecbugs-plugin.jar")
        
        # Run SpotBugs
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
            if not os.path.exists(xml_out):
                return []
            
            tree = ET.parse(xml_out)
            root = tree.getroot()
            
            findings = []
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
            return findings
        except Exception as e:
            print(f"Spotbugs error: {e}")
            return []

def run_pmd(code: str) -> list:
    """Run PMD for java code quality."""
    class_name = _extract_public_class_name(code)
    with tempfile.TemporaryDirectory() as tmpdir:
        java_file = os.path.join(tmpdir, f"{class_name}.java")
        with open(java_file, "w", encoding="utf-8") as f:
            f.write(code)
            
        pmd_home = os.getenv("PMD_HOME", "/opt/tools/pmd-bin-7.0.0")
        report_out = os.path.join(tmpdir, "pmd_out.xml")
        
        # Run PMD
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
            if not os.path.exists(report_out):
                return []
                
            tree = ET.parse(report_out)
            root = tree.getroot()
            findings = []
            
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
            return findings
        except Exception as e:
            print(f"PMD error: {e}")
            return []

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

