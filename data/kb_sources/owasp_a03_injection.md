# OWASP A03:2021 – Injection (CWE-89, CWE-78, CWE-77)

## Overview
Injection flaws occur when untrusted data is sent to an interpreter as part of a command or query.
Attackers can use injection to execute unintended commands or gain unauthorized access to data.
OWASP ranks injection as one of the most critical web application security risks.

## SQL Injection (CWE-89)

SQL injection occurs when user-supplied input is incorporated into a SQL query without proper sanitization.

### Vulnerable Python Example
```python
# DANGEROUS: Direct string formatting in SQL query
username = request.GET['username']
query = "SELECT * FROM users WHERE username = '" + username + "'"
cursor.execute(query)
```

### Secure Python Example – Parameterized Queries
```python
# SAFE: Always use parameterized queries / prepared statements
username = request.GET['username']
cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
```

### Vulnerable Java Example
```java
// DANGEROUS: String concatenation in SQL
String query = "SELECT * FROM users WHERE id = " + userId;
Statement stmt = conn.createStatement();
ResultSet rs = stmt.executeQuery(query);
```

### Secure Java Example – PreparedStatement
```java
// SAFE: Use PreparedStatement with bind parameters
String query = "SELECT * FROM users WHERE id = ?";
PreparedStatement stmt = conn.prepareStatement(query);
stmt.setInt(1, userId);
ResultSet rs = stmt.executeQuery();
```

### Prevention Checklist
- Use parameterized queries or prepared statements for ALL database interactions
- Use an ORM (SQLAlchemy, Hibernate) which handles escaping automatically
- Validate and sanitize all user input before use
- Apply principle of least privilege to database accounts
- Implement Web Application Firewall (WAF) rules for SQL injection patterns

---

## Command Injection (CWE-78)

Command injection occurs when user input is passed to shell commands without proper sanitization.

### Vulnerable Python Example
```python
# DANGEROUS: Passing user input directly to shell
import os
filename = request.GET['file']
os.system("cat " + filename)  # attacker can inject: "; rm -rf /"
```

### Secure Python Example
```python
# SAFE: Use subprocess with a list and never shell=True
import subprocess
filename = request.GET['file']
# Validate filename first
if not filename.isalnum():
    raise ValueError("Invalid filename")
result = subprocess.run(["cat", filename], capture_output=True, shell=False)
```

### Vulnerable Java Example
```java
// DANGEROUS: Runtime.exec with string concatenation
String command = "ls -l " + userInput;
Runtime.getRuntime().exec(command);
```

### Secure Java Example
```java
// SAFE: Use ProcessBuilder with argument list
ProcessBuilder pb = new ProcessBuilder("ls", "-l", "/safe/directory");
pb.redirectErrorStream(true);
Process process = pb.start();
```

### Prevention Checklist
- Never pass user-controlled input to `os.system()`, `eval()`, `exec()`, or shell=True
- Use `subprocess.run()` with a list of arguments, not a string
- Sanitize input to only allow expected characters (allowlist)
- Run processes with minimum required permissions
- Use higher-level APIs that don't invoke the shell

---

## Code Injection / eval() Injection (CWE-77, CWE-95)

### Vulnerable Python Example
```python
# DANGEROUS: eval() on user input
user_code = request.GET['formula']
result = eval(user_code)  # attacker can run any Python code
```

### Secure Python Example
```python
# SAFE: Parse mathematical expressions safely
import ast
import operator

def safe_eval(expr):
    allowed_ops = {ast.Add: operator.add, ast.Sub: operator.sub, ast.Mult: operator.mul}
    # Use ast.literal_eval for safe evaluation of literals only
    return ast.literal_eval(expr)
```

### Prevention
- Never use `eval()` or `exec()` on user-supplied data
- Use `ast.literal_eval()` for safe literal parsing
- Use dedicated expression parsers for formula evaluation

---

## LDAP Injection (CWE-90)

### Vulnerable Example
```python
# DANGEROUS: Unsanitized input in LDAP filter
username = request.GET['username']
ldap_filter = f"(uid={username})"  # inject: *)(uid=*)(\0
```

### Secure Example
```python
# SAFE: Escape special LDAP characters
import ldap3.utils.conv
username = ldap3.utils.conv.escape_filter_chars(request.GET['username'])
ldap_filter = f"(uid={username})"
```

## References
- OWASP Injection: https://owasp.org/Top10/A03_2021-Injection/
- CWE-89 SQL Injection: https://cwe.mitre.org/data/definitions/89.html
- CWE-78 OS Command Injection: https://cwe.mitre.org/data/definitions/78.html
- OWASP SQL Injection Prevention Cheat Sheet
