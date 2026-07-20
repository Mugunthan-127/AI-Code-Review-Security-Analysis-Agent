import subprocess
import os

code = """package com.demo;
import java.sql.*;
public class VulnerableApplication {
    public static void main(String[] args) throws Exception {
        String sql = "SELECT * FROM users WHERE username='" + args[0] + "'";
        Runtime.getRuntime().exec("notepad.exe");
        System.exit(0);
    }
}
"""
with open('/tmp/VulnerableApplication.java', 'w') as f: f.write(code)
res = subprocess.run(['javac', '/tmp/VulnerableApplication.java'], capture_output=True, text=True)
print('javac:', res.returncode, res.stderr)

cmd = ['/opt/tools/spotbugs-4.8.3/bin/spotbugs', '-textui', '-xml:withMessages', '-output', '/tmp/spotbugs_out.xml', '-pluginList', '/opt/tools/findsecbugs-plugin.jar', '/tmp']
res2 = subprocess.run(cmd, capture_output=True, text=True)
print('spotbugs code:', res2.returncode)
print('spotbugs stdout:', res2.stdout)
print('spotbugs stderr:', res2.stderr)

if os.path.exists('/tmp/spotbugs_out.xml'):
    with open('/tmp/spotbugs_out.xml', 'r') as f:
        print("XML:", f.read()[:500])
else:
    print("No XML file created")
