import sys
import os
import json

# Add backend to path so we can import services
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'backend')))

from services.python_analyzer import run_bandit
from services.java_analyzer import run_pmd, run_spotbugs
from agents.security_vuln import BANDIT_OWASP_MAP, SPOTBUGS_OWASP_MAP

def test_java_vulnerable():
    code = """package com.demo;
import java.sql.*;
public class VulnerableApplication {
    public static void main(String[] args) throws Exception {
        String username = "admin";
        String password = "Admin@123";
        String sql = "SELECT * FROM users WHERE username='" + username + "'";
        Runtime.getRuntime().exec("notepad.exe");
        System.exit(0);
        System.out.println(sql);
        System.out.println(password);
    }
}
"""
    print("--- Java Security (Spotbugs) ---")
    spot_res = run_spotbugs(code)
    for r in spot_res:
        mapped = SPOTBUGS_OWASP_MAP.get(r['rule_id'], ("Unknown", "Unknown", None))
        print(f"[{r['severity'].upper()}] {r['rule_id']} -> {mapped}")

    print("\n--- Java Quality (PMD) ---")
    pmd_res = run_pmd(code)
    for r in pmd_res:
        print(f"[{r['severity'].upper()}] {r['rule_id']} - {r['title']}")

def test_python_vulnerable():
    code = """import os
import pickle

password="admin123"
user=input()
eval(user)
exec("print('Hello')")
os.system("dir")
pickle.loads(b"")
"""
    print("\n--- Python Security (Bandit) ---")
    ban_res = run_bandit(code)
    for r in ban_res:
        mapped = BANDIT_OWASP_MAP.get(r['rule_id'], ("Unknown", "Unknown", None))
        print(f"[{r['severity'].upper()}] {r['rule_id']} -> {mapped}")

if __name__ == "__main__":
    print("Running Tests...\n")
    test_java_vulnerable()
    test_python_vulnerable()
