import os
import sys
import json
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'backend')))

from agents.orchestrator import app

vulnerable_java_code = """
package com.demo;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.Statement;

public class VulnerableLogin {

    public static void main(String[] args) throws Exception {

        String username = "admin";
        String password = "Admin123";

        Connection connection = DriverManager.getConnection(
                "jdbc:mysql://localhost:3306/test",
                "root",
                password);

        Statement statement = connection.createStatement();

        String query =
                "SELECT * FROM users WHERE username='"
                        + username + "'";

        statement.executeQuery(query);

        Runtime.getRuntime().exec("notepad.exe");

        System.out.println(query);

        connection.close();
    }
}
"""

def test_vulnerable_java():
    print("[TEST] Running full orchestrator scan on vulnerable Java code...")
    result = app.invoke({
        "code": vulnerable_java_code,
        "language": "java",
        "is_valid": True,
        "syntax_errors": [],
        "findings": [],
        "code_analysis_findings": [],
        "security_findings": [],
        "complexity_findings": [],
        "dependency_findings": []
    })
    
    findings = result.get("findings", [])
    security_findings = result.get("security_findings", [])
    quality_findings = result.get("code_analysis_findings", [])
    health_score = result.get("risk_score", 0)
    risk_percentage = result.get("risk_percentage", 0)
    summary_raw = result.get("summary_text", "{}")
    summary = json.loads(summary_raw) if isinstance(summary_raw, str) else summary_raw

    print("\n================ VULNERABLE SCAN RESULTS ================")
    print(f"Total Merged Findings: {len(findings)}")
    print(f"Security Findings:     {len(security_findings)}")
    print(f"Quality Findings:      {len(quality_findings)}")
    print(f"Health Score:          {health_score}/100")
    print(f"Risk Score:            {risk_percentage}%")
    for idx, f in enumerate(findings, 1):
        print(f"  {idx}. [{f.get('severity', '').upper()}] {f.get('title')} (Line {f.get('line')}, {f.get('owasp_type', f.get('category'))})")
        if f.get("suggested_fix"):
            print(f"     Suggested Fix:\n{f.get('suggested_fix')[:120]}...")
    print("=========================================================\n")

    assert len(findings) > 0, "Expected vulnerabilities to be detected!"
    assert risk_percentage > 0, "Expected non-zero risk score!"
    print("[SUCCESS] Test passed! Vulnerabilities accurately detected.")

if __name__ == "__main__":
    test_vulnerable_java()
