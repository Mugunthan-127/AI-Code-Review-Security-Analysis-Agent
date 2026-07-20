from services.java_analyzer import run_pmd, run_spotbugs

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

print("--- Spotbugs ---")
for r in run_spotbugs(code):
    print(r['rule_id'], r['severity'], r['title'])

print("--- PMD ---")
for r in run_pmd(code):
    print(r['rule_id'], r['severity'], r['title'])
