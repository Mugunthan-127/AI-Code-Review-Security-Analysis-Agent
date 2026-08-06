import os
import sys
import json
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'backend')))

from agents.orchestrator import app

clean_java_code = """
package com.demo.service;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

public class SecureUserService {
    private static final String DB_URL = "jdbc:mysql://localhost:3306/appdb";

    public void printUser(String userId) {
        String sql = "SELECT id, name, email FROM users WHERE id = ?";
        try (Connection connection = DriverManager.getConnection(DB_URL, "app_user", System.getenv("DB_PASS"));
             PreparedStatement preparedStatement = connection.prepareStatement(sql)) {
            
            preparedStatement.setString(1, userId);
            
            try (ResultSet resultSet = preparedStatement.executeQuery()) {
                while (resultSet.next()) {
                    String name = resultSet.getString("name");
                    System.out.println("Found user: " + name);
                }
            }
        } catch (SQLException e) {
            System.err.println("Database error: " + e.getMessage());
        }
    }
}
"""

def test_clean_java():
    print("[TEST] Running full orchestrator scan on clean Java try-with-resources code...")
    result = app.invoke({
        "code": clean_java_code,
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
    complexity_findings = result.get("complexity_findings", [])
    security_findings = result.get("security_findings", [])
    quality_findings = result.get("code_analysis_findings", [])
    health_score = result.get("risk_score", 0)
    risk_percentage = result.get("risk_percentage", 0)
    summary_raw = result.get("summary_text", "{}")
    summary = json.loads(summary_raw) if isinstance(summary_raw, str) else summary_raw

    print("================ SCAN RESULTS ================")
    print(f"Total Merged Findings: {len(findings)}")
    print(f"Complexity Findings:   {len(complexity_findings)}")
    print(f"Security Findings:     {len(security_findings)}")
    print(f"Quality Findings:      {len(quality_findings)}")
    print(f"Health Score:          {health_score}/100")
    print(f"Risk Score:            {risk_percentage}%")
    print(f"PR Overview:           {summary.get('executive_overview')}")
    print("==============================================")

    assert len(findings) == 0, f"Expected 0 findings but got: {findings}"
    assert health_score == 100, f"Expected health score 100 but got {health_score}"
    assert risk_percentage == 0, f"Expected risk percentage 0 but got {risk_percentage}"
    assert "No security vulnerabilities or code quality issues were detected" in summary.get("executive_overview", "")
    print("[SUCCESS] TEST PASSED: Clean Java code produces 0 issues, 100/100 health, 0% risk, and clean PR summary!")

if __name__ == "__main__":
    test_clean_java()
